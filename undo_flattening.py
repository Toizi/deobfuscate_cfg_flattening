#!/usr/bin/python3

import r2pipe
import sys
import os
import json
import re
import sys, json, base64, pprint, zlib
import graph_tool
import graph_tool.topology as gt
import graph_tool.draw as gd
from binascii import unhexlify
from collections import namedtuple
from unicorn import *
from unicorn.x86_const import *
import traceback
import struct
from binascii import hexlify, unhexlify

graph_tool.seed_rng(42)

COL_DISPATCH = 'slateblue1'
COL_LEAF = 'aquamarine4'
COL_OTHER = '#5cc0f9'
def draw_graph_template(g, out='cfg.pdf'):
    """Draws the graph g with some predefined settings"""
    g = g.copy()
    v = g.add_vertex()
    # g.vertex_properties['fillcolor'][v] = COL_DISPATCH
    # g.vertex_properties['vertex_name'][v] = 'dispatcher'
    # v = g.add_vertex()
    g.vertex_properties['fillcolor'][v] = COL_LEAF
    g.vertex_properties['vertex_name'][v] = 'leaves'
    v = g.add_vertex()
    g.vertex_properties['fillcolor'][v] = COL_OTHER
    g.vertex_properties['vertex_name'][v] = 'other'
    gd.graphviz_draw(g,
        gprops={
            'fontsize' : 12,
            'fontname' : 'Courier',
            'splines' : 'polyline',
            # 'bgcolor' : 'azure'
        },
        vprops={
            # 'headport' : 'n',
            # 'tailport' : 's',
            # 'headport' : g.vertex_properties['headport'],
            # 'tailport' : g.vertex_properties['tailport'],
            # 'fillcolor' : 'gray',
            'fillcolor' : g.vertex_properties['fillcolor'],
            'color' : g.vertex_properties['color'],
            'style' : 'filled',
            'shape' : 'box',
            'height': 0.1,
            'width' : 0.3,
            'fontsize' : 32,
            'label' : g.vertex_properties['vertex_name']
        },
        eprops={
            'headport' : 'n',
            # 'tailport' : 's',
            'color' : g.edge_properties['color'],
            'penwidth' : 3, 
            'arrowhead' : 'normal',
            'arrowsize' : 1.5,
        },
        # size=(1000, 1000),
        ratio='auto',
        vsize=0.5,
        layout='dot',
        output=out)
    print('created {}'.format(out))

def get_cfg_and_flattening_info(program_path, draw_graph=True):
    """Expects the function to process to be present in the pwd/func.dot.
    Constructs the dominator tree, finds all leaves and optionally generates a
    color coded CFG progam_cfg.pdf"""
    g = graph_tool.load_graph('func.dot')

    # build dominator tree
    entry = [v for v in g.vertices() if v.in_degree() == 0]
    # if entry[0].out_degree() != 1:
    #     print('error: entry node has more than one out edge {}'.format(entry[0].out_degree()))
    #     exit(1)
    dom = gt.dominator_tree(g, entry[0])
    dt = g.copy()
    dt.clear_edges()

    for j, x in enumerate(dom.a):
        if j == entry[0] or x == entry[0]:
            continue
        edge = dt.add_edge(x, j)
    
    # find "entry" of the flattening by generating transitive closure of dominator tree
    # and finding the one which dominates the most nodes
    # dt_tc = gt.transitive_closure(dt)
    # dispatcher = next(entry[0].out_edges()).target()
    # dispatcher = max(dt_tc.vertices(), key=lambda v : v.out_degree())
    # g.vertex_properties['fillcolor'][dispatcher] = COL_DISPATCH
    
    # debug output
    # # gd.graphviz_draw(dt_tc, output='out_dt_tc.pdf')
    # # draw_graph_template(dt, 'out_dt.pdf')

    # find leaves of flattening
    leaves = []
    for v in dt.vertices():
        if v.out_degree() == 0 and v.in_degree() > 0:
            g.vertex_properties['fillcolor'][v] = COL_LEAF
            leaves.append(v)
    
    # ugly cleaning of a potentially all catching jump back to the top
    # only expects at most 1 of these right now
    for l in leaves:
        v = g.vertex(l)
        # leaves are not allowed to have more than one out edge (0 if return), does not hold for optimized binaries
        # assert v.out_degree() <= 1, 'leaf has more than one out edge %s' % g.vertex_properties['vertex_name'][v]
        for edge in v.out_edges():
            if edge.target() in leaves and edge.target() != v:
                print('Removing catch all leaf {}'.format(g.vertex_properties['vertex_name'][edge.target()]))
                g.vertex_properties['fillcolor'][edge.target()] = COL_OTHER
                del leaves[leaves.index(edge.target())]
                break
    
    # add entry node to leaves
    # print('entry: {}'.format(entry))
    leaves.append(entry[0])
    g.vertex_properties['fillcolor'][entry[0]] = COL_LEAF

    leaves = [ int(g.vertex_properties['vertex_name'][l], base=16) for l in leaves ]

    # for edge in entry[0].out_edges():
    #     if edge.target() == dispatcher:
    #         leaves.append(int(g.vertex_properties['vertex_name'][entry[0]], base=16))
    #         g.vertex_properties['fillcolor'][entry[0]] = COL_LEAF
    #         break

    # draw cfg with color coded nodes
    if draw_graph:
        draw_graph_template(g, program_path + "_cfg.pdf")
    
    return g, leaves


def get_modified_dot(dot_func):
    """Changes colors, removes some unparsable attributes, cleans up label content"""

    lines = [l.strip() for l in dot_func.splitlines(keepends=False) if l != '']
    regex = re.compile(r'(\||\\|/) ')
    for i, line in enumerate(lines):
        line = re.sub(regex, r'', line)
        line = line.replace('white', COL_OTHER)
        line = line.replace('palegreen', COL_OTHER)
        line = line.replace('#7f0000', '#d10404')
        
        lines[i] = line

    start_idx = -1
    for i, line in enumerate(lines):
        if line.startswith('edge '):
            start_idx = i+1
            break
    
    if start_idx < 0:
        print('could not find "edge" in dot representation')
        exit(1)
    for i, line in enumerate(lines[start_idx:-1]):
        idx = line.rfind(']')
        lines[i+start_idx] = '{} {}{}'.format(line[:idx],
            ', headport=n, tailport=s', line[idx:])
    lines.insert(start_idx, 'digraph code {')
    return '\n'.join(lines[start_idx:])


def get_function(program_path, addr):
    """uses r2pipe to dump the specified function as dot to func.dot and returns
    (dot graph as string, function info, function basic blocks,
    function as bytes, bitness)"""
    r2 = r2pipe.open(program_path)
    r2.cmd('s {}'.format(addr))
    r2.cmd('af')
    dot_func = r2.cmd('agfd $$')
    dot_modified = get_modified_dot(dot_func)

    with open('func.dot', 'w', encoding='utf8') as f:
        f.write(dot_modified)
    
    # finfo_buggy = r2.cmdj('pdfj')

    fbbs = r2.cmdj('afbj')
    fbbs = { bb['addr'] : bb for bb in fbbs}

    finfo = {}
    fend = max(_addr + bb['size'] for _addr, bb in fbbs.items())
    finfo['size'] = fend - addr #finfo_buggy['addr']
    finfo['addr'] = addr # finfo_buggy['addr']
    ops = []
    for _, bb in fbbs.items():
        new_ops = r2.cmdj('pdj {} @ {}'.format(bb['ninstr'], bb['addr']))
        ops.extend(new_ops)
    ops = { op['offset'] : op for op in ops }
    finfo['ops'] = ops

    fbytes = unhexlify(r2.cmd('p8 {}'.format(finfo['size'])))

    bitness = r2.cmdj('iAj')['bins'][0]['bits']

    r2.quit()
    return dot_modified, finfo, fbbs, fbytes, bitness

def get_bb_ops(bb, ops):
    """Helper function returning all instructions (sorted by address) from ops
    that are inside the basic block bb"""
    bb_ops = [ op for addr, op in ops.items() if addr >= bb['addr'] and addr < bb['addr'] + bb['size']]
    bb_ops = sorted(bb_ops, key=lambda op : op['offset'])
    return bb_ops

def add_leaf_info(leaf_ends, cmovs, leaf, state_var, bb_ops):
    """Takes a leaf, the state var (register name) and the instructions of the
    leaf basic block and finds any relevant conditional moves + leaf boundary"""
    dbg = False
    if dbg:
        print('leaf 0x{:x} bb_ops: \n\t{}\n'.format(leaf, '\n\t'.join([op['opcode'] for op in bb_ops])))

    # search for cmovs where the dest is the register of the state_var
    for op in reversed(bb_ops):
        if op['type'] != 'cmov':
            continue
        
        opcode = op['opcode'].replace(',', '')
        cmov, dest, src = opcode.split(' ')
        if dest != state_var:
            if dbg:
                print('skipping cmov since dest != state_var: {}'.format(opcode))
            continue
        
        cmovs[op['offset']] = (cmov.replace('cmov', ''), src)
        break

    last_bb_op = bb_ops[-1]
    # initial bb is treated as leaf to avoid unnecessary extra handling but might not end with a jmp/ret
    # assert last_bb_op['type'] == 'jmp' or last_bb_op['type'] == 'ret', 'last op in leaf is not ret/jmp %s' % last_bb_op['type']
    leaf_ends[last_bb_op['offset']] = bb_ops[0]['offset']

def get_flattening_params(leaves, finfo, fbbs, state_var):
    """finds conditional moves, leaf boundaries and register used for routing"""
    dbg = True
    ops = finfo['ops']
    
    # TODO: dynamically find register
    # state_var = 'esi'

    # find all the cmovs/leaf ends
    cmovs = {}
    leaf_ends = {}
    for leaf in leaves:
        bb = fbbs[leaf]
        bb_ops = get_bb_ops(bb, ops)
        add_leaf_info(leaf_ends, cmovs, leaf, state_var, bb_ops)
    
    if dbg:
        print('state_var cmovs:')
        for addr, _ in cmovs.items():
            print('\t0x{:x}: {}'.format(addr, ops[addr]['opcode']))

        print('leaf_ends:')
        for addr, bb_end in leaf_ends.items():
            print('\t0x{:x}: 0x{:x}'.format(addr, bb_end))
    
    return state_var, cmovs, leaf_ends


reg_map = {'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX, 'rcx': UC_X86_REG_RCX, 'rdx': UC_X86_REG_RDX,
    'rbp': UC_X86_REG_RBP, 'rsp': UC_X86_REG_RSP, 'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI,
    'r8': UC_X86_REG_R8, 'r9': UC_X86_REG_R9, 'r10': UC_X86_REG_R10, 'r11': UC_X86_REG_R11, 'r12': UC_X86_REG_R12,
    'r13': UC_X86_REG_R13, 'r14': UC_X86_REG_R14, 'r15': UC_X86_REG_R15, 'rip': UC_X86_REG_RIP,
    'eax': UC_X86_REG_EAX, 'ebx': UC_X86_REG_EBX, 'ecx': UC_X86_REG_ECX, 'edx': UC_X86_REG_EDX,
    'ebp': UC_X86_REG_EBP, 'esp': UC_X86_REG_ESP, 'esi': UC_X86_REG_ESI, 'edi': UC_X86_REG_EDI,
    'r8d': UC_X86_REG_R8D, 'r9d': UC_X86_REG_R9D, 'r10d': UC_X86_REG_R10D, 'r11d': UC_X86_REG_R11D, 'r12d': UC_X86_REG_R12D,
    'r13d': UC_X86_REG_R13D, 'r14d': UC_X86_REG_R14D, 'r15d': UC_X86_REG_R15D, 'eip': UC_X86_REG_EIP}

def state_save(uc):
    """Helper function to save the state of a unicorn emulation instance.
    Returns (saved context, saved memory)"""
    ctx = uc.context_save()
    mem = []
    for begin, end, perms in uc.mem_regions():
        mem.append((begin, end, bytes(uc.mem_read(begin, end - begin))))
    return (ctx, mem)

def state_restore(uc, state):
    """Helper function to restore the state of a unicorn emulation instance.
    Takes unicorn instance, (saved context, saved memory)"""
    ctx, mem = state
    for begin, end, data in mem:
        uc.mem_write(begin, data)
    uc.context_restore(ctx)


def handle_leaf_start(uc, addr):
    """Callback for leaf start. Stops emulation if the leaf has been visited
    already, records leaf as visited, records real target and condition"""
    global real_targets, last_leaf_end, last_opcode, visited_leafs
    if addr in visited_leafs:
        print("Already visited this leaf, stopping")
        uc.emu_stop()
    else:
        visited_leafs.add(addr)

    if last_leaf_end:
        targets = real_targets.get(last_leaf_end, [])
        targets.append((last_opcode, addr))
        real_targets[last_leaf_end] = targets
    last_opcode = None

def handle_leaf_end(uc, addr):
    """Callback for leaf end. Notes the current source + sets jump condition
    to unconditional in case there was no conditionval move in this block"""
    global last_leaf_end, last_opcode
    dbg = True

    last_leaf_end = addr

    # if a leaf ends and there was no cmov, i.e. last_opcode set, it will be an unconditional jmp
    if last_opcode is None:
        last_opcode = 'jmp'

    if dbg:
        print('\tgot leaf end, opcode {}'.format(last_opcode))
        # print('\tgot leaf end, bb starting at 0x{:x}'.format(bb_start))

def handle_cmov(uc, addr, state_var_reg):
    """Callback for conditional move. Saves the state as if the condition was
    negated"""
    global ctx_to_continue, last_cmov, last_leaf_end, last_opcode

    if last_opcode is not None:
        print("WARNING: 0x{:x} several cmovs in a row before a jmp in leaf".format(addr))
    # handle cmovs by saving the state with the value of the other condition
    # for future execution
    (src_reg, src_val), (dst_reg, dst_val), cond = last_cmov
    cur_val = uc.reg_read(state_var_reg)
    # print("handle_cmov: saving state with rip 0x{:x}".format(uc.reg_read(reg_map['rip'])))
    if cur_val == src_val:
        uc.reg_write(dst_reg, dst_val)
        ctx_to_continue.append((state_save(uc), 'jmp'))
        uc.reg_write(dst_reg, cur_val)
        last_opcode = 'j' + cond
    else:
        assert cur_val == dst_val
        uc.reg_write(dst_reg, src_val)
        ctx_to_continue.append((state_save(uc), 'j' + cond))
        uc.reg_write(dst_reg, cur_val)
        last_opcode = 'jmp'
    last_cmov = None
    
def hook_code(uc, address, size, user_data):
    """Unicorn callback for tracing instructions.
    Calls further callbacks for leaf start, conditional move, etc"""
    global real_targets, last_cmov, last_leaf_end, last_opcode
    dbg = True
    state_var_reg, leaf_starts, leaf_ends, cmovs, fops = user_data

    op = fops[address]
    if dbg:
        print('> 0x{:>08x}: {}'.format(address, op['opcode']))
    
    # handle call/ret by skipping/stopping
    op_type = op['type']
    if op_type == 'call':
        uc.reg_write(UC_X86_REG_RIP, address + size)
        if dbg:
            print('\tskipping call')
        return
    elif op_type == 'ret':
        if dbg:
            print('stopping at ret')
        uc.emu_stop()
        return
    
    # last instruction was a conditional move, act on it now
    if last_cmov is not None:
        handle_cmov(uc, address, state_var_reg)
    
    # handle leaf start
    if address in leaf_starts:
        if dbg:
            print('\tgot leaf start')
        handle_leaf_start(uc, address)
    
    # handle end of leaf
    elif address in leaf_ends:
        bb_start = leaf_ends[address]
        handle_leaf_end(uc, address)

    # records the cmov info needed to process it after single stepping
    elif address in cmovs:
        cmov_cond, cmov_reg = cmovs[address]
        cmov_reg_uc_src = reg_map[cmov_reg]
        if dbg:
            print('\tgot cmov 0x{:x}: {}'.format(address, cmov_reg))
        last_cmov = ((cmov_reg_uc_src, uc.reg_read(cmov_reg_uc_src)), (state_var_reg, uc.reg_read(state_var_reg)), cmov_cond)
    

def hook_mem(uc, access, address, size, value, user_data):
    """unicorn callback for invalid memory access.
    Maps the memory range (requires page alignment) and continues execution"""
    dbg = True
    if dbg:
        print('Invalid memory access at 0x{:x}'.format(address))

    if access == UC_MEM_WRITE_UNMAPPED or access == UC_MEM_READ_UNMAPPED:
        uc.mem_map(page_align(address, round_up=False), page_align(size))
    return True

def page_align(addr, round_up=True):
    """Helper function for page alignment"""
    if addr % 0x1000 == 0:
        return addr
    
    return (addr & ~0xfff) + (round_up and 0x1000 or 0)
    
def init_emu(leaf_ends, state_var, cmovs, finfo, fbytes, bitness):
    """sets up memory, sets hooks, etc"""

    BASE_ADDRESS = finfo['addr']
    try:
        mode = UC_MODE_32
        if bitness == 64:
            mode = UC_MODE_64
        emu = Uc(UC_ARCH_X86, mode)
        emu.mem_map(page_align(BASE_ADDRESS, round_up=False), page_align(finfo['size']))

        emu.hook_add(UC_HOOK_MEM_INVALID, hook_mem)
        emu.hook_add(UC_HOOK_CODE, hook_code, user_data=(reg_map[state_var], leaf_ends.values(), leaf_ends, cmovs, finfo['ops']))

        # setup stack
        stack_start = 0x30000
        if bitness == 64:
            stack_start = 0x7ffffffde000
        
        stack_size = 0x21000
        emu.mem_map(stack_start-stack_size, stack_size)
        # should be irrelevant but try not to generate access violation
        middle_of_stack = stack_start - stack_size//2
        emu.reg_write(UC_X86_REG_RSP, middle_of_stack)
        emu.reg_write(UC_X86_REG_RBP, middle_of_stack)

        emu.mem_write(BASE_ADDRESS, fbytes)

        emu.reg_write(UC_X86_REG_RIP, BASE_ADDRESS)
        return emu

    except UcError as e:
        traceback.print_exc()
        print("Unicorn error: {}".format(e))
        exit(1)

def undo_flattening(g, leaves, finfo, fbbs, fbytes, bitness, state_var):
    """Gathers leaf/cmoves info needed, inits emulation and starts it until
    there is no more work left. Returns leaf ends"""
    global real_targets, last_cmov, last_leaf_end, ctx_to_continue, visited_leafs, last_opcode
    state_var, cmovs, leaf_ends = get_flattening_params(leaves, finfo, fbbs, state_var)
    uc = init_emu(leaf_ends, state_var, cmovs, finfo, fbytes, bitness)
    real_targets = {}
    last_cmov = None
    last_leaf_end = None
    ctx_to_continue = []
    visited_leafs = set()
    uc.emu_start(finfo['addr'], finfo['addr'] + finfo['size'], timeout=3*UC_SECOND_SCALE)
    while ctx_to_continue:
        state, last_opcode = ctx_to_continue.pop()
        state_restore(uc, state)
        saved_rip = uc.reg_read(reg_map['rip'])
        print('new rip: 0x{:x}'.format(saved_rip))
        uc.emu_start(saved_rip, finfo['addr'] + finfo['size'], timeout=3*UC_SECOND_SCALE)
    print('real targets: {}'.format(real_targets))
    return leaf_ends

def patch_location(r2, finfo, bb, from_addr, targets):
    """Generates patches for the basic block. Starts at the end and goes back
    as many bytes as needed.
    Returns patches as [(address, patch_bytes, r2 patch argument, r2 patch cmd"""
    dbg = False
    if dbg:
        print('patch_location(_, {}, {:x}, {}'.format(bb, from_addr, targets))
    bb_ops = get_bb_ops(bb, finfo['ops'])
    required_bytes = sum([len(r2.cmd('pa {} {} @ {}'.format(opc, tar, from_addr)))//2 for opc, tar in targets])
    if dbg:
        print('required_bytes: {}'.format(required_bytes))
    
    num_bytes = 0
    for op in reversed(bb_ops):
        num_bytes += op['size']
        if num_bytes >= required_bytes:
            break
    else:
        print('Error: not enough bytes to patch 0x{:x} => {} ({}/{}) '.foramt(from_addr, targets, num_bytes, required_bytes))
        exit(1)

    bb_end = bb['addr'] + bb['size']
    assemble_start = bb_end - num_bytes
    assemble_ea = assemble_start

    # assemble
    patches = []
    for opcode, to_addr in targets:
        patch_str = '{} {}'.format(opcode, to_addr)

        patch_str = '{} {} @ {}'.format(opcode, to_addr, assemble_ea)
        patch = r2.cmd('pa ' + patch_str)
        if not patch:
            print("Could not assemble patch 0x{:x} : {} 0x{:x} ({})".format(assemble_ea, opcode, to_addr, patch_str))
            return None
        patches.append((assemble_ea, patch, patch_str, 'wa'))
        assemble_ea += len(patch)//2
    
    # nop the rest
    if assemble_ea < bb_end:
        patch_str = '{} @ {}'.format(r2.cmd('pa nop') * (bb_end - assemble_ea), assemble_ea)
        patches.append((assemble_ea, '', patch_str, 'wx'))

    if dbg:
        print(patches)

    return patches


def patch_program(program_path, finfo, fbbs, leaf_ends):
    """Patches the program according to the info gathered from the emulation
    using r2pipe"""
    def sort_targets(target):
        opcode, _ = target
        if 'jmp' == opcode:
            return 1
        return 0

    r2 = r2pipe.open(program_path)
    patches = []

    # nop all the routing stuff
    for addr, bb in fbbs.items():
        # we only want to process non-leafs
        if addr in leaf_ends.values():
            # also filter leafs that don't provide a real target
            # should only be artifacts from flattening due to default case
            is_filter = False
            for addr_from in real_targets:
                if bb['outputs'] == 0 or addr <= addr_from and addr_from < addr + bb['size']:
                    break
            else:
                is_filter = True
                print('filtering default case leaf 0x{:x}'.format(addr))
            if not is_filter:
                continue
        
        patch_str = '{} @ {}'.format(r2.cmd('pa nop') * bb['size'], addr)
        patches.append((addr, '', patch_str, 'wx'))

    # get patches for all the real destinations
    for from_addr, targets in real_targets.items():
        local_patches = patch_location(r2, finfo, fbbs[leaf_ends[from_addr]], from_addr, sorted(targets, key=sort_targets))
        if local_patches:
            patches.extend(local_patches)
    r2.quit()
    print('patches: {}'.format(patches))
    with open(program_path, 'rb') as f:
        binary = f.read()
    patched_path = '{}.patched'.format(program_path)
    with open(patched_path, 'wb') as f:
        f.write(binary)
    
    r2 = r2pipe.open(patched_path, ['-w'])
    for addr, patch_bytes, patch_str, patch_cmd in patches:
        print('{} {}'.format(patch_cmd, patch_str))
        r2.cmd('{} {}'.format(patch_cmd, patch_str))
    r2.quit()


def main():
    try:
        program_path = sys.argv[1]
        addr = int(sys.argv[2], base=16)
        state_var = 'eax'
        if len(sys.argv) >= 4:
            state_var = sys.argv[3]
    except:
        print('usage: {} program_path hex_addr'.format(__file__))
        print('example:')
        print('{} fla_test.elf 0x000400500'.format(__file__))
        raise

    dot, finfo, fbbs, fbytes, bitness = get_function(program_path, addr)
    graph, leaves = get_cfg_and_flattening_info(program_path)
    leaf_ends = undo_flattening(graph, leaves, finfo, fbbs, fbytes, bitness, state_var)
    patch_program(program_path, finfo, fbbs, leaf_ends)

if __name__ == '__main__':
    main()
