# This script is used to generate a map from a list of constants.
# The function "_format()" needs to be adapted.
# 
# Example:
# INPUT (in the file "data.txt")
#    const STUN_ATTRIBUT_MAPPED_ADDRESS 	= 0x0001
#    const STUN_ATTRIBUT_RESPONSE_ADDRESS   = 0x0002
#    const STUN_ATTRIBUT_CHANGE_REQUEST		= 0x0003
# OUTPUT
#    STUN_ATTRIBUT_MAPPED_ADDRESS:       "MAPPED_ADDRESS",
#    STUN_ATTRIBUT_RESPONSE_ADDRESS:     "RESPONSE_ADDRESS",
#    STUN_ATTRIBUT_CHANGE_REQUEST:       "CHANGE_REQUEST",


use strict;

my @lines  = ();
my @result = ();

sub _format
{
  my ($in_name) = @_;
  $in_name =~ s/^STUN_ATTRIBUT_(.+)/$1/;
  return $in_name;
}

open(FD, "<data.txt") or die "Can not open data file: $!";
@lines = <FD>;
close FD;

foreach my $line (@lines)
{
  if ($line =~ m/^\s*$/) { next; }
  if ($line =~ m/^\s*const\s+([A-Z_]+)\s*=\s*(0x[0-9A-Fa-f]{4})\s*$/)
  {
    my $name  = $1;
    my $value = $2;

    push(@result, sprintf("\t% -50s \"%s\",", "$name:", _format($name)));
    next;
  }
  die "Invalid line: $line\n";
}

print join("\n", @result);
