# ---+ Extensions
# ---++ XSendFileContrib
# **PERL EXPERT**
# This setting is required to enable executing the xsendfile service from the bin directory
$Foswiki::cfg{SwitchBoard}{xsendfile} = {
  package => 'Foswiki::Contrib::XSendFileContrib',
  function => 'xsendfile',
  context => {xsendfile => 1}
};

# **SELECT none,X-Sendfile,X-LIGHTTPD-send-file,X-Accel-Redirect**
# Enable efficient delivery of static files
# using the xsendfile feature available in apache, nginx and lighttpd.
# Use <ul>
# <li>X-Sendfile for Apache2 </li>
# <li>X-LIGHTTPD-send-file for Lighttpd</li>
# <li>X-Accel-Redirect for Nginx</li>
# </ul>
# Note that you will need to configure your http server accordingly.
$Foswiki::cfg{XSendFileContrib}{Header} = 'none';

# **PATH**
# Location that the http server will process internally to send protected files.
# Leave it to {PubDir} for Lighttpd; use the <code>/protected_files</code> location
# as configured for an Nginx.
$Foswiki::cfg{XSendFileContrib}{Location} = '';

# **REGEX**
# Prefix of a url path to be removed before parsing the rest of it as a web.topic
# For examples thumbnails generated by ImageGalleryPlugin are stored in '/pub/images/'.
# A PathPrefix '/images' covers these kind of urls. ExportPlugin by default stores
# exported files in '/export/assets' and '/export/html'. Below example setting
# covers the three of them.
$Foswiki::cfg{XSendFileContrib}{PathPrefix} = '/(images|export/assets|export/html)';

# **REGEX EXPERT**
# File extensions to default to an "attachment" content disposition.
# This setting is mostly needed for Internet Explorers only as other browser default to
# a "save as" dialog for any content they can't display inline correctly.
$Foswiki::cfg{XSendFileContrib}{DefaultAttachmentDispositionFiles} = '(?:(?:(?:xlt|xls|csv|ppt|pps|pot|doc|dot)(x|m)?)|odc|odb|odf|odg|otg|odi|odp|otp|ods|ots|odt|odm|ott|oth|mpp|rtf|vsd)$';

# **PERL**
# By default view rights of the topic are controlling the access rights to download
# all attachments on this topic. In some cases you might want to use <i>change</i>
# rights to protect attachments being downloaded, or assert special DOWNLOAD rights.
# This can be achieved using an array of {AccessRules} where each rule has got the
# format
# <code>
# {
#   web => "regular expression",
#   topic => "regular expression",
#   file => "regular expression",
#   requiredAccess => "VIEW|CHANGE|DOWNLOAD|...",
# }
# </code>
# These rules will be tested in the given order whenever an attachment is requested.
# When one of the rules matches will the access rights required be checked.
# Normal VIEW access rights are apploed in case where none of the rules apply.
# As a special case a rule of the form requiredAccess => "" means that access is granted
# unconditionally.
$Foswiki::cfg{XSendFileContrib}{AccessRules} = [
  {
      web => "Sandbox",
      topic => "TestUpload",
      file => ".*\.pdf",
      requiredAccess => "CHANGE",
  },
  {
      file => "igp_.*",
      requiredAccess => "",
  },
];

# **BOOLEAN LABEL="Redirect to Login on access denied"**
# Redirect to a login screen or return a plain 401 access denied in case of missing access rights.
# It is recommended to set this to FALSE on public sites to ease the load by web crawlers. Set this
# to TRUE if you want people to log in when accessing a view restricted file shared via email.
$Foswiki::cfg{XSendFileContrib}{RedirectToLoginOnAccessDenied} = $FALSE;

1;
