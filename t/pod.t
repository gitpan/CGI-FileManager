use Test::More;
eval "use Test::Pod 1.24";
plan skip_all => "Test::Pod 1.24 required for testing POD" if $@;
all_pod_files_ok();
