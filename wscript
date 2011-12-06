# === Build DJB NaCl ===
#
# nacl has its own build system, "do".  In a good news/bad news situation, "do"
#  benchmarks all implementations on your machine and picks the one that's
#  fastest and makes sure it produces valid results.  Unfortunately, this makes
#  it very slow.  Other bad news is that it seems to be biased towards the
#  assumption that the source code was perfect as it arrived and so fails to
#  report compilation errors.  This matters when you are trying to fix bugs
#  in the implementation and would like to see the compiler failures you may
#  have caused rather than have to guess why the given object file did not show
#  up in the library. (nb: The only encountered bug has been in the C++
#  binding.)
#
# The general structure of the source tree in do's nomenclature is:
#   operation/primitive/implementation
#  where:
#  - operation is one of the directories named in the OPERATIONS file on its
#     own line.  For example: crypto_box, crypto_stream, etc.
#  - primitive is the algorithm that is used to that end: salsa20, etc.
#  - implementation is the name of an implementation that implements that
#     primitive.  For example: ref, donna_c64, etc.
#
# In the operation directories, besides the sub-directories, we may also find:
#  - measure.c: Performmance measurement of the primitives.
#  - try.c: Unit tests.
#  - wrapper-*.cpp: C++ wrappers
#
# In the primitive directories, we may find files like:
#  - selected: Indicates that this is the default primitive to use for the given
#     operation and that the relevant header glue should be generated.
#  - used: Indicates that the primitive should be available to the library and
#     so should be built.  It just may not be the "selected" primitive.
#  - checksum: Something to do with running the try.c tests; dunno right now.
#
# There are also a few directories with their own special build logic we care
#  about:
#   - randombytes: the .c file needs to be built and the header renamed
#   - inttypes: It detects the right size by doubling the number for the
#      appropriate number of bits (signed versus unsigned) and generating the
#      appropriate header files.  Instead, we manually created some header
#      files that just include stdint.h and perform a typedef.
#  and some we do not care about:
#   - cpuid
#   - okcompilers
#   - cpucycles
# 
# **THE BIGGEST ANNOYANCE WITH DO** is that it builds every implementation with
#  the global "crypto_OP.h" header file pretending that the currently building
#  implementation is the selected primitive and implementation in question (with
#  the resulting #defines to boot.)  Since "do" builds each implementation
#  individually and is constantly creating and destroying stuff, this is
#  reasonable for it, but is annoying for a build system that tries to
#  parallelize things.  We deal with this by mutating the source files so that
#  '#include "OP.h"' becomes '#include "IMPL_PRIM_OP.h" which lives
#  in a private "build-include" directory.
#
# We are using waf here because node uses it.  We are using the 1.6 series
#  instead of the out-of-date 1.5 series because the API docs for 1.6 are
#  readily available.  We aren't using make because we are trying to decrease
#  the pain going on and I like that waf colorizes by default.

import os, os.path, re, platform
from waflib.Task import Task
from waflib import TaskGen

top = '.'
out = 'build'

def slurpFileToList(path):
    '''read the contents of a multi-line file into a whitespace-stripped list'''
    f = open(path, 'r')
    l = [line.strip() for line in f]
    f.close()
    return l

def slurpFile(path):
    '''read the contents of a file and return them'''
    f = open(path, 'r')
    data = f.read()
    f.close()
    return data

OPERATIONS = slurpFileToList('OPERATIONS')
MACROS = slurpFileToList('MACROS')
C_PROTOS = slurpFileToList('PROTOTYPES.c')
CXX_PROTOS = slurpFileToList('PROTOTYPES.cpp')

# nacl's "do" script does some complicated combinations of echo/egrep/sed/while
#  in order to build its various header files.  We attempt to maintain as much
#  of their spirit while making them understandable to mortals such as myself.
#  Although python has a number of fantastic templating engines, we use very
#  simple combinations of manual replacing and list comprehensions to accomplish
#  this.

OPERATION_TEMPLATE = '''#ifndef ${o}_H
#define ${o}_H

#include "${op}.h"

${TRANSFORMED_MACROS}
#define ${o}_PRIMITIVE "${p}"
#define ${o}_IMPLEMENTATION ${op}_IMPLEMENTATION
#define ${o}_VERSION ${op}_VERSION

#endif
'''

def make_operation_header(operation, primitive):
    op_prim = '%s_%s' % (operation, primitive)
    s = OPERATION_TEMPLATE.replace("${o}", operation)
    s = s.replace("${p}", primitive)
    s = s.replace("${op}", op_prim)
    # The original grep/sed/loop filters the contents of MACROS to only include
    #  macros that start with the operation name.  Once it has those, it
    #  defines each macro to map to the name with the operation replaced with
    #  the full operation-primitive.
    # Because we are not particularly performance conscious, we duplicate this
    #  logic, but in longer form.
    macro_lines = []
    for macro in MACROS:
        if not macro == operation and not macro.startswith(operation + '_'):
            continue
        trailing = macro[len(operation):]
        macro_lines.append('#define %s%s %s%s' % (
                             operation, trailing, op_prim, trailing))
    s = s.replace("${TRANSFORMED_MACROS}", '\n'.join(macro_lines))
    return s

OPERATION_PRIMITIVE_TEMPLATE = '''#ifndef ${op}_H
#define ${op}_H

${TRANSFORMED_API_DEFINES}
#ifdef __cplusplus
#include <string>
${TRANSFORMED_CXX_PROTOS}
extern "C" {
#endif
${TRANSFORMED_C_PROTOS}
#ifdef __cplusplus
}
#endif

${TRANSFORMED_MACROS}
#define ${op}_IMPLEMENTATION "${implementation}"
#ifndef ${opi}_VERSION
#define ${opi}_VERSION "-"
#endif
#define ${op}_VERSION ${opi}_VERSION

#endif
'''

def make_operation_primitive_header(api_node, operation, primitive, impl):
    op_prim = '%s_%s' % (operation, primitive)
    op_prim_impl = '%s_%s_%s' % (operation, primitive, impl)
    s = OPERATION_PRIMITIVE_TEMPLATE.replace("${o}", operation)
    s = s.replace("${p}", primitive)
    s = s.replace("${op}", op_prim)
    s = s.replace("${opi}", op_prim_impl)
    s = s.replace("${implementation}", impl)

    # -- api.h transforms
    # the api.h transformation turns "#define CRYPTO_BYTES 32" into
    #  "#define ${opi}_BYTES 32"
    api_str = api_node.read()
    s = s.replace("${TRANSFORMED_API_DEFINES}",
                  api_str.replace("CRYPTO_", '%s_' % (op_prim_impl,)))
    
    # -- prototype transforms
    # like the macro transforms, the goal is to filter the prototypes to those
    #  appropriate for the current operation and then mutate them to fully
    #  reference the op_prim_impl instead of just the operation.
    c_proto_lines = []
    for c_proto in C_PROTOS:
        if c_proto.find(operation) == -1:
            continue
        c_proto_lines.append(c_proto.replace(operation, op_prim_impl))
    s = s.replace('${TRANSFORMED_C_PROTOS}', '\n'.join(c_proto_lines))

    cxx_proto_lines = []
    for cxx_proto in CXX_PROTOS:
        if cxx_proto.find(operation) == -1:
            continue
        cxx_proto_lines.append(cxx_proto.replace(operation, op_prim_impl))
    s = s.replace('${TRANSFORMED_CXX_PROTOS}', '\n'.join(cxx_proto_lines))
    
    # -- macro transforms
    # same deal as in make_operation_header, but the results maps from ${op} to
    #  ${opi} rather than from ${o} to ${op}
    macro_lines = []
    for macro in MACROS:
        if not macro == operation and not macro.startswith(operation + '_'):
            continue
        trailing = macro[len(operation):]
        macro_lines.append('#define %s%s %s%s' % (
                             op_prim, trailing,
                             op_prim_impl, trailing))
    s = s.replace("${TRANSFORMED_MACROS}", '\n'.join(macro_lines))
    return s
    


# Arbitrary priorities for implementations based on their name.
# Note: Our source tree nuked a non-relocatable amd64 assembly implementation
#  of something, so that problem is not reflected in here yet.
IMPL_PRIORITY_BY_NAME = {
  'amd64_xmm6': 12,
  'amd64': 10,
  'donna_c64': 8,
  'core2': -1, # XXX having problem relocating this...
  '53': 5, # better onetimeauth poly1305 impl than x86 which is not relocatable
  'x86_xmm5': 4,
  'x86': 3,
  'inplace': 2,
  'ref': 1,
  'ref2': 1, # wha?
  'portable': 0,
  'athlon': -2, # like a 32-bit athlon with their old proprietary extensions?
}

# Allow providing specific prioritizations on a per-operation basis.  This is
#  being introduced while fighting VM wonkiness.
SPECIFIC_OP_IMPL_OVERRIDES = {
  'crypto_onetimeauth': {
 }
}

def options(opt):
    opt.load('compiler_c compiler_cxx asm')

def configure(conf):
    conf.load('compiler_c compiler_cxx asm')

    #from waflib.Tools import c as Tc
    #TaskGen.extension('.s', Tc.c_hook)

    #flags = ['-O3', '-fomit-frame-pointer', '-funroll-loops', '-fPIC', '-g']
    # O2 actually ends up faster than O3 for us... probably a cache thing.
    flags = ['-O0', '-fPIC'] # -g
    # hack to let android args in easily
    # XXX obviously, this splitting is unsafe on dirs with spaces in them
    cflags = flags[:]
    if 'CFLAGS' in os.environ:
        cflags.extend(os.environ['CFLAGS'].split(' '))
    cppflags = flags[:]
    if 'CPPFLAGS' in os.environ:
        cppflags.extend(os.environ['CPPFLAGS'].split(' '))
    conf.env['CFLAGS'] = cflags
    conf.env['CXXFLAGS'] = cppflags
    
    if 'LDFLAGS' in os.environ:
        conf.env['LDFALGS'] = os.environ['LDFLAGS'].split(' ')
                           

    if 'AS' in os.environ:
        conf.env['AS'] = os.environ['AS']
    else:
        conf.env['AS'] = 'gcc'
    conf.env['ASFLAGS'] = flags
    conf.env['AS_SRC_F'] = '-c'
    conf.env['AS_TGT_F'] = '-o'

def node_is_dir(node):
    return os.path.isdir(node.abspath())


class cryptohdr(Task):
    color = 'PINK'
    def run(self):
        self.outputs[0].write(self.DATA)

class cryptosrc(Task):
    color = 'PINK'
    def run(self):
        self.outputs[0].write(self.DATA)

def figure_implementations(bld):
    '''
    Process the operations to figure out what the source files are, and what the
    right implementations are for each primitive.  Once we have figure out the
    right implementation, we also generate the required header glue.

    waf's node abstraction pretty reliably dumps you back into string space,
    so keep in mind that almost anything we do with a node returns a string
    '''
    src_files = []
    wrapper_files = []
    hdr_files = []
    src_node = bld.path.get_src()
    bld_node = bld.path.get_bld()

    # public include headers
    inc_bld_node = bld_node.make_node('include')
    inc_bld_node.mkdir()

    priv_inc_bld_node = bld_node.make_node('build-include')
    priv_inc_bld_node.mkdir()

    # private include headers

    src_files.append(src_node.find_node('randombytes/devurandom.c'))

    def hdrfy(src_node, targ_node, data):
        hdrgen = cryptohdr(env=bld.env)
        hdrgen.set_inputs(src_node)
        hdrgen.set_outputs(targ_node)
        hdrgen.DATA = data
        
        bld.add_to_group(hdrgen)

    def srcfy(src_node, targ_node, data):
        srcgen = cryptosrc(env=bld.env)
        srcgen.set_inputs(src_node)
        srcgen.set_outputs(targ_node)
        srcgen.DATA = data
        
        bld.add_to_group(srcgen)

    randbytes_h_src = src_node.find_node('randombytes/devurandom.h')
    randbytes_h_node = inc_bld_node.make_node('randombytes.h')
    hdrfy(randbytes_h_src, randbytes_h_node, randbytes_h_src.read())

    # XXX PLATFORM MAGIC
    # waf does not seem to have obvious/sufficiently documented platform
    #  affordances, so we are going to roll our own using the 'platform' module
    #  here.
    # Our build goals are as follows (for same-platform):
    # - Linux: build 32-bit or 64-bit as befits the system setup which we are
    #    basing on whether the python is 32-bit or 64-bit.
    # - OS X: build 64-bit.  (We could build a fat binary, but we want different
    #    implementations based on the cpu architecture we're targeting.)
    # - Windows: build 32-bit, because that's what firefox builds.
    platsys = platform.system()
    platx86 = True
    if platsys == 'Darwin':
        plat64 = True
    elif platsys.find('WIN') != -1 or platsys.find('NT') != -1:
        plat64 = False
    elif platsys == 'Linux':
        plat64 = platform.architecture()[0] == '64bit'
    else:
        raise Exception('Unable to figure out platform.  Sorry :(')

    # XXX Android cross-platform hack
    # we ideally would prefer to figure this out from the compiler itself.
    if 'CFLAGS' in os.environ:
        # our helper script has us manually include the path...
        if (os.environ['CFLAGS'].find('android') != -1 and
              os.environ['CFLAGS'].find('arm') != -1):
            plat64 = False
            platx86 = False

    def pick_best_impl(node, operation):
        '''
        Pick the best implementation in a given primitive directory.
        '''
        best_pri = -100
        best_node = None
        for impl_name in node.listdir():
            # skip 64 bit implementations on non-64 bit platforms
            if not plat64 and impl_name.find('64') != -1:
                continue
            if not platx86 and impl_name.find('x86') != -1:
                continue
            if not platx86 and impl_name.find('athlon') != -1:
                continue
            if not platx86 and impl_name.find('core2') != -1:
                continue
            impl_node = node.make_node([impl_name])
            if not node_is_dir(impl_node):
                continue
            # no api.h => not an actual implementation (or one we nuked but
            #  apparently are not competent at removing all traces of in git)
            if impl_node.find_node('api.h') is None:
                continue
 
            # start with the default priority mapping
            use_priority = IMPL_PRIORITY_BY_NAME[impl_name]
            # let specific operation overrides be processed
            if (SPECIFIC_OP_IMPL_OVERRIDES.has_key(operation) and
                SPECIFIC_OP_IMPL_OVERRIDES[operation].has_key(impl_name)):
                use_priority = SPECIFIC_OP_IMPL_OVERRIDES[operation][impl_name]

            if  use_priority > best_pri:
                best_pri = use_priority
                best_node = impl_node
        return best_node

    def figure_primitive(operation, node, force_selected):
        '''
        Given a primitive directory, figure out if it is used/selected, and if
        so, figure out the best implementation to use and generate the required
        header glue if required.
        '''
        selected = (node.find_node('selected') is not None) or force_selected
        used = (node.find_node('used') is not None)

        if not used:
            #print 'IGNORING', operation, node.name
            return

        primitive = node.name;

        impl_node = pick_best_impl(node, operation)
        impl_name = impl_node.name
        print '  Selected', impl_name, 'for', (operation + ':' + primitive)

        # create the operation-primitive header (we must be used if here)
        api_node = impl_node.find_node('api.h')
        op_prim_header_node = inc_bld_node.make_node(
            '%s_%s.h' % (operation, primitive))
        hdrfy(api_node, op_prim_header_node,
              make_operation_primitive_header(api_node,
                                              operation, primitive, impl_name))


        # generate the operation header string...
        private_op_header_str = make_operation_header(operation, primitive)

        # write it to the build path for the module (but NOT PUBLIC)
        private_op_header_node = priv_inc_bld_node.make_node(
            '%s_%s_%s.h' % (impl_name, primitive, operation))
        # XXX the api_node is not the true origin
        hdrfy(api_node, private_op_header_node, private_op_header_str)

        # mutate the source files
        prim_src_nodes = impl_node.ant_glob(incl=['*.c', '*.s'])
        for prim_src_node in prim_src_nodes:
            prim_bldsrc_node = prim_src_node.get_bld()

            data = prim_src_node.read()
            data = data.replace('"%s.h"' % (operation,),
                                '"%s"' % (private_op_header_node.name,))
            srcfy(prim_src_node, prim_bldsrc_node, data)

            src_files.append(prim_bldsrc_node)

        # copy across any header files (assuming verbatim is cool)
        prim_hdr_nodes = impl_node.ant_glob(incl=['*.h'])
        for prim_hdr_node in prim_hdr_nodes:
            prim_bldhdr_node = prim_hdr_node.get_bld()

            data = prim_hdr_node.read()
            hdrfy(prim_hdr_node, prim_bldhdr_node, data)


        # also write it to the public include dir if appropriate
        if selected:
            #print 'Primitive %s selected for operation %s' % (
            #    node.name, operation)
            op_header_node = inc_bld_node.make_node(
                '%s.h' % (operation,))
            # XXX not true origin
            hdrfy(api_node, op_header_node, private_op_header_str)
        

    # -- iterate over operations
    for op in OPERATIONS:
        op_node = src_node.find_node(op)
        
        any_selected_prim = False
        num_prims = 0
        # - count primitives for inferring selected...
        for kid_name in op_node.listdir():
            op_kid_node = op_node.make_node([kid_name])
            # - primitive?
            if node_is_dir(op_kid_node):
                num_prims += 1
        # - iterate over primitives/wrappers/other
        for kid_name in op_node.listdir():
            op_kid_node = op_node.make_node([kid_name])
            # - primitive?
            if node_is_dir(op_kid_node):
                if figure_primitive(op, op_kid_node, num_prims == 1):
                    any_selected_prim = True
            # - no, a wrapper or something
            elif op_kid_node.name.startswith('wrapper-'):
                wrapper_files.append(op_kid_node)

        # - create a dummy prim file if none was selected
        #if not any_selected_prim:
        #    inc_bld_node.make_node('%s.h' % (op,)).write(
        #        '// dummy; none selected')

    bld.stlib(
        features='c cxx asm',
        source = src_files + wrapper_files,
        # we put private headers in each impl build dir...
        includes = ['./stdints', priv_inc_bld_node, inc_bld_node],
        target = 'nacl'
        )


    bld.shlib(
        features='c asm',
        source = src_files,
        # we put private headers in each impl build dir...
        includes = ['./stdints', priv_inc_bld_node, inc_bld_node],
        target = 'nacl'
        )
        

def build(bld):
    sources = figure_implementations(bld)
