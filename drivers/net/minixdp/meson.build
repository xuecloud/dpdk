if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources = files('rte_eth_mini_xdp.c')

bpf_dep = dependency('libbpf', required: false, method: 'pkg-config')
if not bpf_dep.found()
    bpf_dep = cc.find_library('bpf', required: false)
endif

if bpf_dep.found() and cc.has_header('bpf/xsk.h') and cc.has_header('linux/if_xdp.h')
    ext_deps += bpf_dep
else
    build = false
    reason = 'missing dependency, "libbpf"'
endif
