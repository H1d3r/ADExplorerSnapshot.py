"""
Treeview metadata enrichment functionality.

Detects if treeview metadata is missing and reconstructs it if needed.
"""

from enum import Enum
import logging
import shutil
import struct
from pathlib import Path
from adexpsnapshot.treeview.section_encoder import build_nc_tree, build_stub_nc_tree, encode_section
from adexpsnapshot.treeview.structure import treeview_structure
from adexpsnapshot.treeview.synthetic import create_synthetic_objects_data

TREEVIEW_MAGIC_ADES = b'\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF'  # Likely ADES / populated
TREEVIEW_MAGIC_BOF  = b'\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF'  # Likely BOF / unpopulated

class TreeviewStatus(Enum):
    INVALID = 0
    MISSING = 1
    UNPOPULATED = 2
    POPULATED = 3

def check_treeview_exists(snap):

    treeview_offset = snap.header.treeviewOffset
    if treeview_offset == 0:
        return TreeviewStatus.INVALID
    
    snap.fh.seek(treeview_offset)
    magic = snap.fh.read(8)
    
    if magic == TREEVIEW_MAGIC_ADES:
        header_data = snap.fh.read(20)
        if len(header_data) < 20:
            return TreeviewStatus.MISSING
        else:
            return TreeviewStatus.POPULATED

    if magic == TREEVIEW_MAGIC_BOF:
        return TreeviewStatus.UNPOPULATED

    return TreeviewStatus.INVALID

def get_output_filename(input_path):
    """
    Generate output filename: input.enriched.ext
    
    Examples:
    - snapshot.dat -> snapshot.enriched.dat
    - snapshot -> snapshot.enriched
    - file.xyz -> file.enriched.xyz
    """
    path = Path(input_path.name)
    
    if path.suffix:
        # Has extension: insert .enriched before it
        stem = path.stem
        suffix = path.suffix
        new_name = f"{stem}.enriched{suffix}"
    else:
        # No extension: just append .enriched
        new_name = f"{path.name}.enriched"
    
    return input_path.parent / new_name

def enrich_snapshot(ades):
    snap = ades.snap
    snapshot_path = Path(ades.snapfile.name)
        
    treeview_status = check_treeview_exists(snap)
    
    if treeview_status == TreeviewStatus.POPULATED:
        logging.info("Treeview metadata already exists, aborting.")
        return True
    elif treeview_status == TreeviewStatus.UNPOPULATED:
        logging.info("Treeview metadata is unpopulated, reconstructing...")
    elif treeview_status == TreeviewStatus.MISSING:
        logging.warning("Treeview metadata was expected but missing, reconstructing...")
    elif treeview_status == TreeviewStatus.INVALID:
        logging.error("Treeview metadata is invalid, cannot enrich snapshot")
        return False

    # Use existing preprocessing with cache
    ades.preprocessCached()
    dncache = ades.dncache
        
    # Identify NC roots from the snapshot
    if not ades.domain_dn or not ades.config_dn or not ades.schema_dn or not ades.forest_dn:
        logging.error("No domain, config, schema, or forest root found in snapshot!")
        return False
    
    domain_dns_zones_root = f"DC=DomainDnsZones,{ades.domain_dn}"
    forest_dns_zones_root = f"DC=ForestDnsZones,{ades.forest_dn}"

    logging.info(f"Domain root: {ades.domain_dn}")
    logging.info(f"Config root: {ades.config_dn}")
    logging.info(f"Schema root: {ades.schema_dn}")
    logging.info(f"Domain DNS Zones root: {domain_dns_zones_root}")
    logging.info(f"Forest DNS Zones root: {forest_dns_zones_root}")
    
    # Check which optional NCs exist
    has_domain_dns = any(dn.endswith(domain_dns_zones_root) for dn in dncache.keys())
    has_forest_dns = any(dn.endswith(forest_dns_zones_root) for dn in dncache.keys())
    
    # Build trees and collect missing parents on-demand
    logging.info("Building trees...")
    synthetic_collector = {}  # Will be populated during tree building
    
    domain_tree = build_nc_tree(snap, ades.domain_dn, lambda dn: dn.endswith(ades.domain_dn) and not dn.endswith(ades.config_dn) and not dn.endswith(domain_dns_zones_root) and not dn.endswith(forest_dns_zones_root), dncache, synthetic_collector)
    config_tree = build_nc_tree(snap, ades.config_dn, lambda dn: dn.endswith(ades.config_dn) and not dn.endswith(ades.schema_dn), dncache, synthetic_collector)
    schema_tree = build_nc_tree(snap, ades.schema_dn, lambda dn: dn.endswith(ades.schema_dn), dncache, synthetic_collector)
    if schema_tree is None:
        logging.info(
            "No Schema NC objects in snapshot; using synthetic schema root for treeview"
        )
        schema_tree = build_stub_nc_tree(ades.schema_dn, synthetic_collector)

    missing_required = [name for name, tree in (("Domain", domain_tree), ("Configuration", config_tree), ("Schema", schema_tree)) if tree is None]
    if missing_required:
        logging.error(f"Missing required NC tree(s): {', '.join(missing_required)}. Snapshot may be incomplete; cannot enrich.")
        return False

    domain_dns_zones_tree = None
    if has_domain_dns:
        domain_dns_zones_tree = build_nc_tree(snap, domain_dns_zones_root, lambda dn: dn.endswith(domain_dns_zones_root), dncache, synthetic_collector)

    forest_dns_zones_tree = None
    if has_forest_dns:
        forest_dns_zones_tree = build_nc_tree(snap, forest_dns_zones_root, lambda dn: dn.endswith(forest_dns_zones_root), dncache, synthetic_collector)
    
    # Build section names
    section_trees = [domain_tree, config_tree, schema_tree]
    if domain_dns_zones_tree:
        section_trees.append(domain_dns_zones_tree)
    if forest_dns_zones_tree:
        section_trees.append(forest_dns_zones_tree)

    # Create synthetic objects for all missing parents found during tree building
    synthetic_data = b''
    if synthetic_collector:
        logging.info(f"Creating {len(synthetic_collector)} synthetic containers...")
        
        # Synthetics go at treeview_offset
        synthetic_objects, synthetic_data = create_synthetic_objects_data(
            set(synthetic_collector.keys()), snap, snap.header.treeviewOffset
        )
        
        # Update all trees with actual synthetic object offsets
        def update_synthetics(node):
            """Recursively update synthetic nodes with real obj_offset."""
            dn = node['dn']
            if node['obj_idx'] < 0:
                node['obj_offset'] = synthetic_objects[dn]
            for child in node.get('children', []):
                update_synthetics(child)
        
        for tree in section_trees:
            update_synthetics(tree)
    
    # Encode all sections
    sections = []
    for tree in section_trees:
        section_data = bytes(encode_section(tree))
        sections.append(section_data)
    
    # Calculate header size
    tv_header_size = 16 + (len(section_trees) * 4)
    
    # Calculate section offsets (relative to treeview start, after header)
    # Layout: [Treeview Header][Section1][Section2][...]
    section_offsets = []
    current_offset = tv_header_size
    for section in sections:
        section_offsets.append(current_offset)
        current_offset += len(section)
    
    tv_header_struct = treeview_structure.TreeviewHeader()
    tv_header_struct.magic = 0xFFFFFFFFFFFFFFFE  # Combined 64-bit magic
    tv_header_struct.num_NCs = len(section_trees)  # Dynamic: 3-5 depending on DNS zones presence
    tv_header_struct.reserved = 0
    tv_header_struct.section_offsets = section_offsets
    
    tv_header = tv_header_struct.dumps()
    
    # Create enriched file by copying original snapshot first
    output_path = get_output_filename(snapshot_path)
    logging.info(f"Writing enriched snapshot to: {output_path}")
    try:
        shutil.copyfile(snapshot_path, output_path)
    except OSError as exc:
        logging.error(f"Failed to copy snapshot: {exc}")
        return False
    
    # Update treeviewOffset in main file header if we have synthetic objects
    # New treeview starts after synthetic objects
    old_treeview_offset = snap.header.treeviewOffset
    new_treeview_offset = snap.header.treeviewOffset + len(synthetic_data)
        
    with open(output_path, 'r+b') as out:
        if snap.header.winAdSig != b'win':
            logging.info("Fixing header signature")
            out.seek(0)
            out.write(b'win')
        
        if synthetic_data:
            out.seek(snap.header.fields['treeviewOffset'].offset)
            out.write(struct.pack("<Q", new_treeview_offset))

            out.seek(old_treeview_offset)
            out.write(synthetic_data)

            logging.info(f"Updated treeview offset: 0x{old_treeview_offset:x} → 0x{new_treeview_offset:x}")
        
        out.seek(new_treeview_offset)
        
        # Write treeview metadata: [Header][Sections...]
        out.write(tv_header)
        for section in sections:
            out.write(section)
        
        out.truncate(out.tell())
    
    return True