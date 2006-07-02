
use Test::More;

eval "use Test::Pod::Coverage 1.08";
if ($@) {
    plan skip_all => 
        "Test::Pod::Coverage 1.08 required for testing POD coverage";
} else {
    plan tests => 1;
}
#all_pod_coverage_ok();
pod_coverage_ok( "CGI::FileManager", "CGI::FileManager::Auth" );

