# Module of Foswiki - The Free and Open Source Wiki, https://foswiki.org/
#
# Copyright (C) 2013-2017 Michael Daum http://michaeldaumconsulting.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version. For
# more details read LICENSE in the root of this distribution.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# As per the GPL, removal of this notice is prohibited.

package Foswiki::Contrib::XSendFileContrib;

use strict;
use warnings;
use Encode ();
use Foswiki::Sandbox ();
use Foswiki::Func ();
use Foswiki::Time ();
use File::MMagic ();
use File::Spec ();
use Error qw( :try );
use Foswiki::AccessControlException ();

our $VERSION = '5.21';
our $RELEASE = '12 Dec 2017';
our $SHORTDESCRIPTION = 'A viewfile replacement to send static files efficiently';
our $mimeTypeInfo;
our $mmagic;

sub _decodeUntaint {
  my ($text, $sub) = @_;

  $text = Encode::decode_utf8($text) if $Foswiki::UNICODE;
  $text = Foswiki::Sandbox::untaint($text, $sub) if $sub;

  return $text;
}

sub xsendfile {

  my $session = shift;
  my $request = $session->{request};
  my $response = $session->{response};

  # remove cookie
  $response->cookies([]);

  my $web = $session->{webName};
  my $topic = $session->{topicName};
  my $fileName = $request->param('filename');

  my $pathInfo = $request->path_info();
  my $pathPrefix = "";

  my $headerName = $Foswiki::cfg{XSendFileContrib}{Header} || 'X-LIGHTTPD-send-file';
  my $location = $Foswiki::cfg{XSendFileContrib}{Location} || $Foswiki::cfg{PubDir};
  my $fileLocation;

  my $filePath;
  my $foundOnDisk = 0;

  if (defined $Foswiki::cfg{XSendFileContrib}{PathPrefix} && $pathInfo =~ s/^($Foswiki::cfg{XSendFileContrib}{PathPrefix})//) {
    $pathPrefix = $1;
  }

  my @path = split(/\/+/, $pathInfo);
  shift(@path) unless $path[0];

  # work out the web, topic and filename
  my @web;
  my $pel = _decodeUntaint($path[0], \&Foswiki::Sandbox::validateWebName);

  while ($pel && Foswiki::Func::webExists(join('/', @web, $pel))) {
    push(@web, $pel);
    shift(@path);
    $pel = _decodeUntaint($path[0], \&Foswiki::Sandbox::validateWebName);
  }

  $web = join('/', @web);

  unless ($web) {
    $response->status(404);
    $response->print("404 - no web found\n");
    return;
  }

  # Must set the web name, otherwise plugins may barf if
  # they try to manipulate the topic context when an oops is generated.
  $session->{webName} = $web;

  # The next element on the path has to be the topic name
  $topic = _decodeUntaint(shift @path, \&Foswiki::Sandbox::validateTopicName);

  # check whether this is a file already
  $filePath = File::Spec->catfile("/", $Foswiki::cfg{PubDir}, $pathPrefix, $web, $topic);
  if (-f $filePath) {
    $foundOnDisk = 1;
    $fileLocation = $location . $pathPrefix . '/' . $web . '/' . $topic;

    # test for a file extension, e.g. System/WebHome.html
    if ($topic =~ /^(.*)\.([^\.]+)$/) {
      $fileName = $topic;
      $topic = $1;
    } else {
      $fileName = $topic;
    }
  }

  unless ($topic) {
    $response->status(404);
    $response->print("404 - no topic found\n");
    return;
  }

  # See comment about webName above
  $session->{topicName} = $topic;

  unless (defined $fileName) {
    # What's left in the path is the attachment name.
    $fileName = File::Spec->catfile(@path);
  } else {
    $fileName = Foswiki::urlDecode($fileName);
  }

  # check whether this is a file already
  if (!$foundOnDisk && $fileName) {
    $filePath = File::Spec->catfile("/", $Foswiki::cfg{PubDir}, $pathPrefix, $web, $topic, $fileName);
    if (-f $filePath) {
      $foundOnDisk = 1;
      $fileLocation = $location . $pathPrefix . '/' . $web . '/' . $topic . '/' . $fileName;
    }
  }

  # not found
  if (!defined($fileName) || $fileName eq '') {
    $response->status(404);
    $response->print("404 - no file found\n");
    return;
  }

  $fileName = _decodeUntaint($fileName, \&sanitizeAttachmentName);

  #print STDERR "web=$web, topic=$topic, fileName=$fileName\n";

  # invalid
  unless (defined $fileName) {
    $response->status(404);
    $response->print("404 - file not valid\n");
    return;
  }

  my $topicObject = Foswiki::Meta->load($session, $web, $topic);

  # not found
  if (!$foundOnDisk && !$topicObject->existsInStore()) {
    $response->status(404);
    $response->print("404 - topic $web.$topic does not exist\n");
    return;
  }

  # not found
  if (!$foundOnDisk && !$topicObject->hasAttachment($fileName)) {
    $response->status(404);
    $response->print("404 - attachment $fileName not found at $web.$topic\n");
    return;
  }

  # unauthorized
  unless (checkAccess($topicObject, $fileName, $session->{user})) {
    if ($Foswiki::cfg{XSendFileContrib}{RedirectToLoginOnAccessDenied}) {
      throw Foswiki::AccessControlException("VIEW", $session->{user}, $web, $topic, "access denied");
    } else {
      $response->header(-type => 'text/plain; charset=utf-8');
      $response->status(403);
      $response->print("403 - access denied\n");
    }
    return;
  }

  # check whether we can return a 304 not modified
  $filePath = File::Spec->catfile($Foswiki::cfg{PubDir}, $pathPrefix, $web, $topic, $fileName)
    unless defined $filePath;

  my @stat = stat($filePath);
  my $lastModified = Foswiki::Time::formatTime($stat[9] || $stat[10] || 0, '$http', 'gmtime');
  my $ifModifiedSince = $request->header('If-Modified-Since') || '';
  my $mimeType = mimeTypeOfFile($fileName);

  if ($lastModified eq $ifModifiedSince) {
    $response->header(-status => 304,);
    return;
  }

  # check for rev parameter and fallback if not current
  my $rev = $request->param('rev');
  if (defined $rev) {

    my $fileMeta = $topicObject->get('FILEATTACHMENT', $fileName);
    if ($fileMeta && $fileMeta->{version} > $rev) {

      $response->header(
        -status => 200,
        -type => $mimeType,
        -content_disposition => "inline; filename=\"$fileName\"",
        -last_modified => $lastModified,
      );

      my $fh = $topicObject->openAttachment($fileName, '<', version => $rev);
      $response->body(<$fh>);
    }
  } else {
  
    my $dispositionMode = $request->param('disposition');

    unless (defined $dispositionMode) {
      my $defaultAttachmentDispositionFiles = $Foswiki::cfg{XSendFileContrib}{DefaultAttachmentDispositionFiles}
        || '(?:(?:(?:xlt|xls|csv|ppt|pps|pot|doc|dot)(x|m)?)|odc|odb|odf|odg|otg|odi|odp|otp|ods|ots|odt|odm|ott|oth|mpp|rtf|vsd)$';

      $dispositionMode = ($fileName =~ /$defaultAttachmentDispositionFiles/) ? "attachment" : "inline";
    }

    $fileLocation = $location . $pathPrefix . '/' . $web . '/' . $topic . '/' . $fileName unless defined $fileLocation;

    $response->header(
      -status => 200,
      -type => $mimeType,
      -content_disposition => "$dispositionMode; filename=\"$fileName\"",
      -last_modified => $lastModified,
      $headerName => $fileLocation,
    );
  }

  return;
}

sub checkAccess {
  my ($topicObject, $fileName, $user) = @_;

  if (defined $Foswiki::cfg{XSendFileContrib}{AccessRules}) {
    my $web = $topicObject->web;
    my $topic = $topicObject->topic;
    foreach my $rule (@{$Foswiki::cfg{XSendFileContrib}{AccessRules}}) {
      #print STDERR "rule: web=".($rule->{web}||'').", topic=".($rule->{topic}||'').", file=".($rule->{file}||'').", requiredAccess=".($rule->{requiredAccess}||'')."\n";
      if ((!defined($rule->{web}) || $web =~ /^$rule->{web}$/) &&
          (!defined($rule->{topic}) || $topic =~ /^$rule->{topic}$/) &&
          (!defined($rule->{file}) || $fileName =~ /^$rule->{file}$/)) {

        return 1 if !defined($rule->{requiredAccess}) || $rule->{requiredAccess} eq "";
        return $topicObject->haveAccess($rule->{requiredAccess}, $user);
      }
    }
  } 

  # fallback
  #print STDERR "checking ACLS for user $user\n";
  return $topicObject->haveAccess("VIEW", $user);
}

sub mimeTypeOfFile {
  my $fileName = shift;

  if ($fileName && $fileName =~ /\.([^.]+)$/) {
    my $suffix = $1;

    $mimeTypeInfo = Foswiki::Func::readFile($Foswiki::cfg{MimeTypesFileName}) 
      unless defined $mimeTypeInfo;

    if ($mimeTypeInfo =~ /^([^#]\S*).*?\s$suffix(?:\s|$)/im) {
      return $1;
    }
  }

  $mmagic = File::MMagic->new() unless defined $mmagic;

  my $mimeType = $mmagic->checktype_filename($fileName);

  if (defined $mimeType && $mimeType ne "x-system/x-error") {
    #print STDERR "mmagic says $mimeType to $fileName\n";
    return $mimeType;
  }

  #print STDERR "unknown mime type of $fileName\n";

  return 'application/octet-stream';
}

sub sanitizeAttachmentName {
  my $fileName = shift;

  $fileName =~ s{[\\/]+$}{};    # Get rid of trailing slash/backslash (unlikely)
  $fileName =~ s!^.*[\\/]!!;    # Get rid of leading directory components
  $fileName =~ s/[\*?~^\$@%`"'&;|<>\[\]#\x00-\x1f]//g; # Get rid of a subset of Namefilter

  return Foswiki::Sandbox::untaintUnchecked($fileName);
}

1;
