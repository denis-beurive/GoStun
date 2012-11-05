# This script is used to generate code from the following web site:
# http://www.iana.org/assignments/stun-parameters/stun-parameters.xml
# 
# Example:
# INPUT (in the file "data.xml")
#    <registry id="stun-parameters-6">
#      <title>STUN Error Codes</title>
#      <xref type="rfc" data="rfc5389"/>
#      <registration_rule>IETF Review</registration_rule>
#      <record>
#        <value>0-299</value>
#        <description>Reserved</description>
#       </record>
#       ...
# OUTPUT
#    const STUN_ERROR_TRY_ALTERNATE  = 300;
#    const STUN_ERROR_BAD_REQUEST    = 400;
#    const STUN_ERROR_UNAUTHORIZED   = 401;
#    ...
#    STUN_ERROR_TRY_ALTERNATE:       "TRY_ALTERNATE",
#    STUN_ERROR_BAD_REQUEST:         "BAD_REQUEST",
#    STUN_ERROR_UNAUTHORIZED:        "UNAUTHORIZED",


use strict;
use warnings;

use XML::Simple;

my $parser = XML::Simple->new( KeepRoot => 1 );
my $doc    = $parser->XMLin('data.xml');
my @consts = (); 
my @map    = ();

foreach my $entry ( @{$doc->{'registry'}->{'record'}} )
{
  my $value = $entry->{'value'};
  my $desc  = $entry->{'description'};

  unless($value =~ m/^\d+$/) { next; }
  $desc =  uc($desc);
  $desc =~ s/ /_/g;

  push(@consts, sprintf("const % -45s = %d;", "STUN_ERROR_$desc", $value));
  push(@map,    sprintf("\t% -45s \"%s\",", "STUN_ERROR_${desc}:", $desc));
} 

print join("\n", @consts);
print "\n\n";
print join("\n", @map);
