#!/usr/bin/perl -wT
use strict;

$ENV{PATH}= "";
use lib "../lib";
use CGI::FileManager;
my $fm = CGI::FileManager->new(
			PARAMS => {
				AUTH => {
					PASSWD_FILE => "../authpasswd",
				}
			}
		);
=pod
		PARAMS => {
			HTML_TEMPLATES => "/home/gabor/work/dev/CGI-Filemanager/templates",
		}
	);
=cut
$fm->run;

