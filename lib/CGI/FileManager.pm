package CGI::FileManager;

use warnings;
use strict;

=head1 NAME

CGI::FileManager - Managing a directory structure on an HTTP server

=head1 Synopsis

Enable authenticated users to do full file management on
a subdirectory somewhere with a web server installed.

After installing the module you have to create a file with usernames and passwords
in it. For this we supply cfm-passwd.pl which should have been installed in your PATH.
Type:

> cfm-passwd.pl /home/user/mypwfile add someuser

It will ask for password and the home directory that the use is supposed to be able to
manage.

Then in nearby CGI script:

 #!/usr/bin/perl -wT
 use strict;
 
 use CGI::FileManager;
 my $fm = CGI::FileManager->new(
			PARAMS => {
				AUTH => {
					PASSWD_FILE => "/home/user/mypwfile",
				}
			}
		);
 $fm->run;

Now point your browser to the newly created CGI file and start managing your files.


=head1 WARNING

 This is Software is in Alpha version. Its interface, both human and programatic
 *will* change. If you are using it, please make sure you always read the Changes
 section in the documentation.


=head1 Version

Version 0.01


=cut

=head1 Description


=head1 Methods

=cut

our $VERSION = '0.01';

use base 'CGI::Application';
use CGI::Application::Session;
use CGI::Upload;
use File::Spec;
use File::Basename;
use Data::Dumper;
use HTML::Template;
#use Fcntl qw(:flock);
#use POSIX qw(strftime);
#use File::Copy;
use Carp qw(cluck croak);


use CGI::FileManager::Auth;
my $cookiename = "cgi-filemanager";


#Standard CGI::Application method
#Setup the Session object and the default HTTP headers

sub cgiapp_init {
	my $self = shift;
	CGI::Session->name($cookiename);
	$self->session_config(
#		CGI_SESSION_OPTIONS => [ "driver:File", $self->query, {Directory => "/tmp"}],
		COOKIE_PARAMS       => {
				-expires => '+24h',
				-path    => '/',
#				-domain  => $ENV{HTTP_HOST},
		},
		SEND_COOKIE         => 1,
	);
	
	$self->header_props( 
		-expires => '-1d',  
		# I think this this -expires causes some strange behaviour in IE 
		# on the other hand it is needed in Opera to make sure it won't cache pages.
		-charset => "utf-8",
	);
	$self->session_cookie();
}



# modes that can be accessed without a valid session
my @free_modes = qw(login login_process logout about redirect); 
my @restricted_modes = qw(list_dir change_dir upload_file delete_file create_directory remove_directory); 


# Regular CGI::Appication method to setup the list of all run modes and the default run mode 
sub setup {
	my $self = shift;
	$self->start_mode("list_dir");
	my %modes;
	foreach my $mode (@free_modes, @restricted_modes) {
		$modes{$mode} = $mode;
	}
	#$modes{"AUTOLOAD"} = "autoload";
	$self->run_modes(%modes);
}

# Regular CGI::Application method
sub cgiapp_prerun {
	my $self = shift;
	my $rm = $self->get_current_runmode();

	$SIG{__WARN__} = sub {
		if ($_[0] !~ /Replacing previous run mode/) {
			warn $_[0];
		}
	}; # silence the unnecessary warning about changing run_mode
	return if grep {$rm eq $_} @free_modes;

	# Redirect to login, if necessary
	if (not  $self->session->param('loggedin') ) {
		$self->header_type("redirect");
		$self->header_props(-url => "http://$ENV{HTTP_HOST}$ENV{SCRIPT_NAME}?rm=login");
		$self->prerun_mode("redirect");
		return;
	}
}


# Just to easily redirect to the home page
sub redirect {
    my $self = shift;
	return;
#	my $target = shift;
#    $self->header_type("redirect");
#    $self->header_props(-url => "http://$ENV{HTTP_HOST}/$target");
}
    


# Change the default behaviour of CGI::Application by overriding this
# method. By default we'll load the template from within our module.
sub load_tmpl {
	my $self = shift;
	my $name = shift;
	
	my $template = _get_template($name);
	croak "Could not load template '$name'" if not $template;

	my $t = HTML::Template->new_scalar_ref(\$template, @_);

#	my $t = $self->SUPER::load_tmpl(@_, 
#		      die_on_bad_params => -e ($self->param("ROOT") . "/die_on_bad_param") ? 1 : 0
#	);
	return $t;
}

# Print an arbitrary message to the next page
sub message {
	my $self = shift;
	my $message = shift;
	
	my $t = $self->load_tmpl(
			"message",
	);

	$t->param("message" => $message) if $message;
	return $t->output;
}


# Show login form
sub login {
	my $self = shift;
	my $errs = shift;
	my $q = $self->query;
	
	my $t = $self->load_tmpl(
			"login",
			associate => $q,
	);

	$t->param($_ => 1) foreach @$errs;
	return $t->output;
}


# Processing the login information, checking authentication, configuring the session object
# or giving error message.
sub login_process {
	my $self = shift;
	my $q = $self->query;

	if (not $q->param("username") or not $q->param("password")) {
		return $self->login(["login_failed"]);
	}

	my $auth = $self->authenticate();
	if ($auth->verify($q->param("username"), $q->param("password"))) {
		$self->session->param(loggedin => 1);
		$self->session->param(username => $q->param("username"));
		$self->session->param(homedir  => $auth->home($q->param("username")));
#		$self->session->param(workdir  => $auth->home($q->param("username")));
		$self->header_type("redirect");
		$self->header_props(-url => "http://$ENV{HTTP_HOST}$ENV{SCRIPT_NAME}");
		return;
	} else {
		return $self->login(["login_failed"]);
	}
}

# see details in POD
sub authenticate {
	my $self = shift;
	return CGI::FileManager::Auth->new($self->param("AUTH"));
}


# logout and mark the session accordingly.
sub logout {
	my $self = shift;
	$self->session->param(loggedin => 0);
	my $t = $self->load_tmpl(
			"logout",
	);
	$t->output;
}


sub _untaint_path {
	my $path = shift;

	return "" if not defined $path;
	return "" if $path =~ /\.\./;
	if ($path =~ m{^([\w./-]+)$}) {
		return $1;
	}

	return "";
}


# Changes the current directory and then lists the new current directory
sub change_dir {
	my $self = shift;
	my $q = $self->query;

	my $workdir = _untaint_path $q->param("workdir");
	my $homedir = $self->session->param("homedir");

	my $dir = $q->param("dir");
	if (not defined $dir) {
		warn "change_dir called without a directory name\n";
		return $self->list_dir;
	}
		
	# check santity of the directory
	# something else, does this directory exist ?
	if ($dir eq "..") {
		# ".." are we at the root ?
		if ($workdir eq "") {
			# do nothing (maybe a beep ?)
			return $self->list_dir;
		} else {
			# shorten the path by one
			$workdir = dirname $workdir;
			$self->header_type("redirect");
			$self->header_props(-url => "http://$ENV{HTTP_HOST}$ENV{SCRIPT_NAME}?rm=list_dir;workdir=$workdir");
			return $self->redirect;
			#Redirect
			return $self->list_dir;
		}
	} else {
		if ($dir =~ /\.\./) {
			warn "change_dir: Two dots ? '$dir'";
			return $self->message("Hmm, two dots in a regular file ? Please contact the administrator");
		}
		if ($dir =~ /^([\w.-]+)$/) {
			$dir = $1;
			$workdir = File::Spec->catfile($workdir, $dir);
			my $path = File::Spec->catfile($homedir, $workdir);
			if (-d $path) {
				$self->header_type("redirect");
				$self->header_props(-url => "http://$ENV{HTTP_HOST}$ENV{SCRIPT_NAME}?rm=list_dir;workdir=$workdir");
				return $self->redirect;
				#$self->session->param(workdir => $workdir);
				#return $self->list_dir;
			} else {
				# after changing directory people might press back ...
				# and then the whole thing can get scread up not only the change directory
				# but if they now delete a file that happen to exist both in the current directory
				# and in its parent (which is currenly shown in the browser) the file will be deleted
				# from the "current directory", I think the only solution is that the user supplies us
				# with full (virtual) path name for every action.
				# This seems to be easy regarding action on existing files as they are all done by clicking
				# on links and the links can contain.
				# Regardin upload/create dir and later create file we have to know where should the thing go
				# - what does the user think is the current working directory. For such operations we can
				# hide the workdir in a hidden field in the form.
				#
				# In either case we have to make sure the full virtual directory is something the user
				# has right to access.
				 
				#my $workdir_name = basename $workdir;
				#if ($workdir_name eq $dir) {
				#	return $self->message("Heuristics !");
				#} else {
					warn "change_dir: Trying to change to invalid directory ? '$workdir'$dir'";
					return $self->message("It does not seem to be a correct directory. Please contact the administrator");
				#}
			}
		} else {
			warn "change_dir: Bad regex, or bad visitor ? '$dir'";
			return $self->message("Hmm, we don't recognize this. Please contact the administrator");
		}
	}
	
	warn "should never got here....";
	return $self->list_dir;
}

# Listing the content of a directory
sub list_dir {
	my $self = shift;
	my $msgs = shift;

	my $q = $self->query;

	my $workdir = _untaint_path $q->param("workdir");
	my $homedir = $self->session->param("homedir");
	my $path = File::Spec->catfile($homedir, $workdir);


	my $t = $self->load_tmpl(
			"list_dir",
		 	associate => $q,
			loop_context_vars => 1,
	);
	if (opendir my $dh, $path) {
		my @entries = grep {$_ ne "." and $_ ne ".."} readdir $dh;
		if ($workdir ne "" and $workdir ne "/") {
			unshift @entries, "..";
		}
		my @files;
		
		foreach my $f (@entries) {
			my $full = File::Spec->catfile($path, $f);
			push @files, {
				filename    => $f,
				filetype    => _file_type($full),
				subdir      => -d $full,
				filedate    => scalar (localtime((stat($full))[9])),
				size        => (stat($full))[7],
				delete_link => $f eq ".." ? "" : _delete_link($full),
				workdir     => $workdir,
			};
		}	
		
		$t->param(workdir => $workdir);
		$t->param(files   => \@files);
		$t->param(version => $VERSION);
	}
	$t->param($_ => 1) foreach @$msgs;

	return $t->output;
}

# returns the type of the given file
sub _file_type {
	my ($file) = @_;
	return "dir"  if -d $file;
	return "file" if -f $file;
	return "n/a";
}

sub _delete_link {
	my ($file) = @_;
	return "rm=remove_directory;dir="  if -d $file;
	return "rm=delete_file;filename="  if -f $file;
	return "";
}


				
# Delete a file from the server
sub delete_file {
	my $self = shift;
	my $q = $self->query;

	my $filename = $q->param("filename");
	$filename = _untaint($filename);

	if (not $filename) {
		warn "Tainted filename: '" . $q->param("filename") . "'";
		return $self->message("Invalid filename. Please contact the system administrator");
	}
	my $homedir = $self->session->param("homedir");
	my $workdir = _untaint_path $q->param("workdir");
	
	$filename = File::Spec->catfile($homedir, $workdir, $filename);

	unlink $filename;

	$self->list_dir;
}

sub remove_directory {
	my $self = shift;
	my $q = $self->query;

	my $dir = $q->param("dir");
	$dir = _untaint($dir);

	if (not $dir) {
		warn "Tainted diretory name: '" . $q->param("dir") . "'";
		return $self->message("Invalid directory name. Please contact the system administrator");
	}
	my $homedir = $self->session->param("homedir");
	my $workdir = _untaint_path $q->param("workdir");
	
	$dir = File::Spec->catfile($homedir, $workdir, $dir);

	rmdir $dir;

	$self->list_dir;
}


sub _untaint {
	my $filename = shift;

	return if not defined $filename;

	return if $filename =~ /\.\./;
	if ($filename =~ /^([\w.-]+)$/) {
		return $1;
	}
	return;
}

sub upload_file {
	my $self = shift;
	my $q = $self->query;

	my $homedir = $self->session->param("homedir");
	my $workdir = _untaint_path $q->param("workdir");

	my $upload = CGI::Upload->new();
	my $file_name = $upload->file_name('filename');
	my $in = $upload->file_handle('filename');
	
	if (ref $in ne "IO::File") {
		warn "No file handle in upload ? '$file_name'";
		return $self->message("Hmm, strange. Please contact the administrator");
	}

	if ($file_name =~ /\.\./) {
		warn "two dots in upload file ? '$file_name'";
		return $self->message("Hmm, we don't recognize this. Please contact the administrator");
	}
	if ($file_name =~ /^([\w.-]+)$/) {
		$file_name = $1;
		if (open my $out, ">", File::Spec->catfile($homedir, $workdir,$file_name)) {
			my $buff;
			while (read $in, $buff, 500) {
				print $out $buff;
			}
		} else {
			warn "Could not open local file: '$file_name'";
			return $self->message("Could not open local file. Please contact the administrator");
		}
	} else {
		warn "Invalid name for upload file ? '$file_name'";
		return $self->message("Hmm, we don't recognize this. Please contact the administrator");
	}

	$self->list_dir;
}

sub create_directory {
	my $self = shift;
	my $q = $self->query;

	my $homedir = $self->session->param("homedir");
	my $workdir = _untaint_path $q->param("workdir");
	my $dir = $q->param("dir");
	$dir = _untaint($dir);
	if (not $dir) {
		warn "invalid directory: '" . $q->param("dir") . "'";
		return $self->message("Invalid directory name ? Contact the administrator");
	}

	mkdir File::Spec->catfile($homedir, $workdir, $dir);

	$self->list_dir;
}

=head1 DESCRIPTION

Enables one to do basic file management operations on a 
filesystem under an HTTP server. The actions on the file system
provide hooks that let you implement custom behavior on each 
such event.

It can be used as a base class for a simple web application
that mainly manipulates files.

=head2 DEFAULT

To get the default behavior you can write the following code.
The module will use the built in templates to create the pages.

 #!/usr/bin/perl -wT
 use strict;
 
 use CGI::FileManager;
 my $fm = CGI::FileManager->new(
			PARAMS => {
				AUTH => {
					PASSWD_FILE => "/home/user/mypwfile",
				}
			}
		);
 $fm->run;


=over 4

=item new(OPTIONS)

=item authenticate

Called without parameter.
Returns an objects that is capable to authenticate a user.

By default it returns a CGI::FileManager::Auth object.

It is planned that this method will be overriden by the user to be able to replace the
authentication back-end. Currently the requirements from the returned object is to have 
these methods:

 $a->verify(username, password)   returns true/false
 $a->home(username)               return the full path to the home directory of the given user

WARNING: 
this interface might change in the future, before we reach version 1.00 Check the Changes.

=back

=head2 META-DATA

Theoretically we could manage some meta-data about each file in some database that
can be either outside our virtual file system or can be a special file in each 
directory.


=cut

# Hmm, either this module does not deal at all with authentication and assumes that 
# something around it can deal with this.

# But we also would like to be able to create a list of users and for each user to assign
# a virtual directory. Onto this virtual directory we would like to be able to "mount"
# any subdirectory of the real file system. We can even go further and provide options
# to this "mount" such as read-only (for that specific user) or read/write.
#=head2 Quota
#Maybe we can also implement some quota on the file system ?


=head2 Limitations

The user running the web server has to have read/write access on the relevant part
of the file system in order to carry out all the functions.

=head1 USE CASES

=head2 Virtual web hosting with no ftp access for one user

A single user needs authentication and full access to one directory tree.
This does not work yet.
 
 #!/usr/bin/perl -T
 
 use CGI::FileManager;
 my $fm = CGI::FileManager->new({
             ROOT => "/home/gabor/web/client1",
	     AUTH => ["george", "WE#$%^DFRE"],   # the latter is the crypt-ed password we expect
             });
 $fm->run;

=head2 Virtual web hosting with no ftp access for a number of users

A number of users need authentication and full access to one directory tree per user.

 #!/usr/bin/perl -T
 
 use CGI::FileManager;
 my $fm = CGI::FileManager->new(
			PARAMS => {
				AUTH => {
					PASSWD_FILE => "/home/user/mypwfile",
				}
			}
		);
 $fm->run;

 The mypwfile file looks similar to an /etc/passwd file:
 username:password:uid:gid:geco:homedir:shell

 gid and shell are currently not used
 homedir is the directory the user has rights for
 password is encrypted by crypt
 uid is just a unique number

=head1 Changes


=head2 v0.01 2004 June 27

 Initial release

=head1 TODO

 Show most of the error messages on the directory listing page

 Test all the functions, look for security issues !
 Show the current directory  (the virtual path)
 Separate footer/header
 Enable external templates

 More fancy things:
 Create file
 Copy file/directory
 Move file/directory
 Unzip file (tar/gz/zip)
 Edit file (simple editor)


=head1 Author

Gabor Szabo, C<< <gabor@pti.co.il> >>

=head1 Bugs

Please report any bugs or feature requests to
C<bug-cgi-filemanager@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org>.  I will be notified, and then you'll automatically
be notified of progress on your bug as I make changes.


=head1 Copyright & License

Copyright 2004 Gabor Szabo, All Rights Reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=head1 See also

CGI::Upload, WWW::FileManager, CGI::Uploader

=cut

    #<link rel="stylesheet" href="/s/style.css" type="text/css">

sub _get_template {
	my $name = shift;

	my %tmpl;

my $css = <<CSS;
<style type="text/css">
BODY
{
    FONT-SIZE: 14px;
    COLOR: #a5a5a5;
    FONT-FAMILY: Verdana;
    BACKGROUND-COLOR: lightblue;
    TEXT-DECORATION: none
}
.error {
	color: red;
}

.mybutton {
    color: #4a4d4a;
	background-color:#8080FF;
	font-size:12px;
	font-weight:bold;
    /*
	FONT-FAMILY: Verdana,arial;
    TEXT-DECORATION: none
	*/
}
.choosebutton {
    color: #4a4d4a;
	font-size:12px;
	font-weight:bold;
    /*
	FONT-FAMILY: Verdana,arial;
    TEXT-DECORATION: none
	*/
}


A:link
{
    FONT-SIZE: 12px;
    COLOR: #339900;
    FONT-FAMILY: verdana;
    TEXT-DECORATION: none
}
A:visited
{
    FONT-SIZE: 12px;
    COLOR: #996600;
    FONT-FAMILY: Verdana;
    TEXT-DECORATION: none
}
A:hover
{
    FONT-SIZE: 12px;
    COLOR: #cc9900;
    FONT-FAMILY: Verdana;
    TEXT-DECORATION: none
}
A:active
{
    FONT-SIZE: 12px;
    COLOR: #000033;
    FONT-FAMILY: Verdana;
    TEXT-DECORATION: none
}

.files TABLE
{
	cell-spacing:   1;
	cell-padding:   0;
	border:         1;
	align:          middle;
}

.files TH
{
	background-color: #8080FF;
}

TD
{
    FONT-SIZE: 13px;
    COLOR: #4a4d4a;
    FONT-FAMILY: Verdana,arial;
    TEXT-DECORATION: none
}

TH
{
	FONT-SIZE: 13px;
    COLOR: #4a4d4a;
    FONT-FAMILY: Verdana,arial;
    TEXT-DECORATION: none
}

.even TD {
	FONT-SIZE: 13px;
    COLOR: #4a4d4a;
    FONT-FAMILY: Verdana,arial;
    TEXT-DECORATION: none;
	background-color: #CCFF99;
}

.odd TD {
	FONT-SIZE: 13px;
    COLOR: #4a4d4a;
    FONT-FAMILY: Verdana,arial;
    TEXT-DECORATION: none;
	background-color: #AAFF99;
}



</style>
CSS


$tmpl{message} = <<ENDHTML;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML> 
<HEAD>
	<TITLE>CGI::FileManager</TITLE>  
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
    CSS_STYLE_SHEET
</HEAD> 
<body>
<p>Message</p>
<TMPL_VAR message>
</body>
<HTML>
ENDHTML


$tmpl{login} = <<ENDHTML;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML> 
<HEAD>
	<TITLE>CGI::FileManager</TITLE>  
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
    CSS_STYLE_SHEET
</HEAD> 
<body>
<form method="POST"><br><br><br><br><br><br><br><br>
<center>
<TMPL_IF login_failed><div class="error">Login failed</div></TMPL_IF>
<table bgcolor="#006666" cellspacing="1" cellpadding="0" border="0" align="middle">
<tr><td bgcolor="#8080FF" colspan=2 align="middle"><B>Login form</B><input type="hidden" name="rm" value="login_process"></td></tr>
<tr><td bgcolor="#CCFF99">Username:</td> <td><input name="username" value="<TMPL_VAR username>"></td></tr>
<tr><td bgcolor="#CCFF99">Password:</td> <td> <input name="password" type="password"></td></tr>
<tr><td bgcolor="#CCFF99" colspan=2 align="middle"><input type="submit" value="Login"></td></tr>
</table></center>
</body>
<HTML>
ENDHTML

$tmpl{list_dir} = <<ENDHTML;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML> 
<HEAD>
	<TITLE>CGI::FileManager - Directory Listing</TITLE>  
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
    CSS_STYLE_SHEET
</HEAD> 
<body><br><br>
<center>

<TMPL_IF files>
<div class="files">
<table>
 <tr>
   <th>name</th>
   <th>type</th>
   <th>date</th>
   <th>size</th>
   <th></th>
 </tr>
 <TMPL_LOOP files>
  <tr class="<TMPL_IF NAME="__odd__">odd<TMPL_ELSE>even</TMPL_IF>">
  	<TMPL_IF subdir>
	  <td>
	    <a href="?rm=change_dir;workdir=<TMPL_VAR workdir>;dir=<TMPL_VAR filename>">
		<TMPL_VAR filename>
		</a>
	  </td>
	<TMPL_ELSE>
	  <td><TMPL_VAR filename></td>
	</TMPL_IF>
	<td><TMPL_VAR filetype></td>
	<td><TMPL_VAR filedate></td>
	<td><TMPL_VAR size></td>
	<td><TMPL_IF delete_link><a href="?workdir=<TMPL_VAR workdir>;<TMPL_VAR delete_link><TMPL_VAR filename>">delete</a></TMPL_IF></td>
  </tr>
 </TMPL_LOOP>
</table>
</div>
</TMPL_IF>

<br><br>
<table  cellspacing="0" cellpadding="0" border="0" align="middle">
<TR><TD align="middle" colspan=2><hr></TD></TR>

 <tr><td align="right" valign="top">
<form method="POST">
<input type="hidden"  name="rm" value="create_directory">
<input type="hidden"  name="workdir" value="<TMPL_VAR workdir>">
<input name="dir" size="15"></TD><TD>
<input type="submit"  class="mybutton" value="Create Directory">
</form>
</TD></TR>
<TR><TD align="middle" colspan=2><hr></TD></TR>
<TR><TD colspan=2 align="left">

  <form method="POST" enctype="multipart/form-data">
  <input type="hidden" name="workdir" value="<TMPL_VAR workdir>">
  <input type="hidden" name="rm" value="upload_file">
  <input type="file" size="16" name="filename" class="choosebutton">
  <input type="submit" class="mybutton" value="Upload">
  </form>

</TD></TR>
<TR><TD align="middle" colspan=2><hr></TD></TR>
<TR><TD align="right"></TD>
    <TD align="left">
     <table>
       <tr>
	   <td>
        <form method="POST">
        <input type="hidden" name="rm" value="list_dir">
        <input type="hidden" name="workdir" value="<TMPL_VAR workdir>">
        <input type="submit" class="mybutton" value="Refresh">
        </form>
       </td>
       <td>
        <form method="POST">
        <input type="hidden" name="rm" value="logout">
        <input type="submit" class="mybutton" value="Logout">
        </form>
       </td>
	   </tr>
	 </table>
   </TD>
</TR></table>

<table  cellspacing="0" cellpadding="0" border="0" align="middle">

<TR><TD colspan=2 align="middle">
You are using CGI::FileManager Version: <TMPL_VAR version>
<br>
For help contact <a href="mailto:gabor\@pti.co.il">Gabor Szabo</a>
</TD></TR></table>

</center>
</body>
</html>
ENDHTML




$tmpl{logout} = <<ENDHTML;
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML> 
<HEAD>
	<TITLE>CGI::FileManager - Good bye</TITLE>  
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
    CSS_STYLE_SHEET
</HEAD> 
<body>
<p>
You were successfully logged out.
</p>
<form method="POST">
<input type="submit" value="Login again">
</form>
</body>
<HTML>
ENDHTML


	$tmpl{$name} =~ s/CSS_STYLE_SHEET/$css/;


	return $tmpl{$name};

}

1; 

