"""
Builds the treeview structure for a naming context.
"""

from collections import defaultdict
from io import BytesIO
from adexpsnapshot.treeview.structure import treeview_structure

def build_nc_tree(snap, nc_root, nc_filter, dncache=None, synthetic_collector=None):
    """
    Build tree for a naming context.
    
    Args:
        snap: Snapshot object
        nc_root: Root DN of this NC
        nc_filter: Filter function for DNs
        dncache: DN to index cache
        synthetic_collector: Optional dict to collect synthetic DN -> True for missing parents
    
    Returns:
        Tree dict or None
    """
    dn_to_info = {}
    
    # Add real objects from cache
    for dn, obj_idx in dncache.items():
        if nc_filter(dn):
            dn_to_info[dn] = {
                'obj_idx': obj_idx,
                'obj_offset': snap.objectOffsets[obj_idx],
                'dn': dn
            }
    
    if not dn_to_info:
        return None  # No objects found in this NC
    
    children_map = defaultdict(list)
    
    def get_parent_dn(dn):
        r"""
        Extract parent DN, handling escaped commas.
        LDAP DNs use backslash escaping: CN=Smith\, John,OU=Users
        """
        # Find first unescaped comma
        i = 0
        while i < len(dn):
            if dn[i] == ',' and (i == 0 or dn[i-1] != '\\'):
                # Found unescaped comma - parent is everything after
                return dn[i+1:] if i+1 < len(dn) else None
            i += 1
        return None  # No parent (root)
    
    # Build parent-child relationships, creating synthetics on-demand
    # Use negative indices as temporary IDs for synthetic nodes
    next_synthetic_idx = -1
    newly_created = []  # Track synthetics to process after main loop
    
    for dn in list(dn_to_info.keys()):
        if dn == nc_root:
            continue
        
        parent = get_parent_dn(dn)
        if parent:
            # Create synthetic entries for all missing ancestors
            current = parent
            while current and current not in dn_to_info:
                if nc_filter(current):
                    # Mark for synthetic creation
                    if synthetic_collector is not None:
                        synthetic_collector[current] = True
                    # Create placeholder entry with temporary negative index
                    temp_idx = next_synthetic_idx
                    dn_to_info[current] = {
                        'obj_idx': temp_idx,
                        'obj_offset': 0,  # Placeholder, will be updated
                        'dn': current
                    }
                    newly_created.append(current)
                    next_synthetic_idx -= 1
                current = get_parent_dn(current)
                if current == nc_root:
                    break
            
            # Now add to children map
            if parent in dn_to_info:
                children_map[parent].append(dn)
    
    # Process newly created synthetic DNs to add them to their parents' children_map
    for dn in newly_created:
        parent = get_parent_dn(dn)
        if parent and parent in dn_to_info:
            children_map[parent].append(dn)
    
    root_dn = min(dn_to_info.keys(), key=len)
    
    def build_node(dn):
        info = dn_to_info[dn]
        child_dns = children_map.get(dn, [])
        return {
            **info,
            'children': [build_node(c) for c in child_dns]
        }
    
    return build_node(root_dn)


def build_stub_nc_tree(nc_root, synthetic_collector=None):
    """
    Build a minimal single-node NC tree when a naming context has no LDAP objects.

    Bloodhound-style snapshots omit Schema NC enumeration but ADExplorer still
    expects a Schema section in treeview metadata.
    """
    if synthetic_collector is not None:
        synthetic_collector[nc_root] = True

    return {
        'obj_idx': -1,
        'obj_offset': 0,
        'dn': nc_root,
        'children': [],
    }


def encode_section(tree):
    """
    Universal section encoder using cstruct for type safety.
    
    Works identically for Domain, Configuration, and Schema NCs.
    No special cases, pure algorithm based on tree structure.
    
    Optimization: Leaf children are stored ONLY inline in their parent,
    not as standalone entries (eliminates redundancy).
    """
    
    # Flatten tree to get all nodes
    def flatten(node):
        result = [node]
        for c in node.get('children', []):
            result.extend(flatten(c))
        return result
    
    all_nodes = flatten(tree)
    
    # PASS 1: Identify which nodes need standalone entries
    # Leaf children are stored inline in parent - they don't need standalone entries
    inline_only = set()
    
    def mark_inline_leaves(node):
        """Mark leaf children that will be stored inline only."""
        children = node.get('children', [])
        for child in children:
            if not child.get('children'):
                # This is a leaf child - will be stored inline in parent
                inline_only.add(child['obj_idx'])
            else:
                # Recursively check this child's children
                mark_inline_leaves(child)
    
    mark_inline_leaves(tree)
    
    # PASS 2: Compute positions and cache children classification
    # Only allocate positions for: root, parents, and children-with-children
    node_word_positions = {}
    node_metadata = {}
    current_word_pos = 0
    
    for node in all_nodes:
        obj_idx = node['obj_idx']
        
        # Skip leaf children - they're stored inline in parent only
        if obj_idx in inline_only:
            continue
        
        node_children = node.get('children', [])
        
        # Position this node
        node_word_positions[obj_idx] = current_word_pos
        
        # Classify children ONCE
        entries_with_children = []
        entries_without_children = []
        for c in node_children:
            if c.get('children'):
                entries_with_children.append(c)
            else:
                entries_without_children.append(c)

        # ParentNode size: header(16) + child_offsets(count*4) + inline_child_offsets(count*8)
        size = 4 + len(entries_with_children) + len(entries_without_children) * 2

        # Cache for PASS 3 (just the lists, compute len() when needed)
        node_metadata[obj_idx] = (entries_with_children, entries_without_children)

        current_word_pos += size
    
    # PASS 3: Write data using cstruct structures
    output = BytesIO()
    output.write(b'\x00' * (current_word_pos * 4))  # Pre-allocate
    
    for node in all_nodes:
        obj_idx = node['obj_idx']
        
        # Skip inline-only nodes
        if obj_idx in inline_only:
            continue
        
        word_pos = node_word_positions[obj_idx]
        byte_pos = word_pos * 4
        
        output.seek(byte_pos)
        
        # Write ParentNode structure (all non-inline nodes are parents)
        entries_with_children, entries_without_children = node_metadata[obj_idx]
        
        parent = treeview_structure.ParentNode()
        parent.objectOffset = node['obj_offset']
        parent.num_children_with_children = len(entries_with_children)
        parent.num_children_without_children = len(entries_without_children)
        
        # Build child_offsets array (relative byte offsets to child ParentNode entries)
        parent.child_offsets = []
        for child in entries_with_children:
            child_word_pos = node_word_positions[child['obj_idx']]
            relative_byte_offset = (child_word_pos - word_pos) * 4
            parent.child_offsets.append(relative_byte_offset)
        
        # Build inline_child_offsets array (direct objectOffsets for leaf children)
        parent.inline_child_offsets = []
        for child in entries_without_children:
            parent.inline_child_offsets.append(child['obj_offset'])
        
        output.write(parent.dumps())
    
    return output.getvalue()



