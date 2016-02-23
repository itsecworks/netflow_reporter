#!/usr/bin/perl
# Original code:
# http://search.cpan.org/~akoba/Net-Flow-0.03/lib/Net/Flow.pm
#
#
# for dbi perl lib and mysql server required:
# libdbi-perl
# mysql-server

use strict;
use Net::Flow qw(decode);
use IO::Socket::INET;
use DBI;
use Time::HiRes qw(time);
use POSIX qw(strftime);

# Palo Alto Templates info:
# Source from Palo Alto Link: https://www.paloaltonetworks.com/documentation/61/pan-os/pan-os/reports-and-logging/netflow-templates.html#48263
# interface numbers:https://www.paloaltonetworks.com/documentation/61/pan-os/pan-os/reports-and-logging/identify-firewall-interfaces-in-external-monitoring-systems.html#62695
# and from perl net::flow output 

my $PATemplateId256={

	'SetId'        =>0,
	'TemplateId'   =>256,
	'Template'=>[
				{ 'Length' => 8, 'Id' => 1  }, # IN_BYTES
				{ 'Length' => 4, 'Id' => 2  }, # IN_PKTS
				{ 'Length' => 1, 'Id' => 4  }, # PROTOCOL
				{ 'Length' => 1, 'Id' => 5  }, # TOS
				{ 'Length' => 1, 'Id' => 6  }, # TCP_FLAGS
				{ 'Length' => 2, 'Id' => 7  }, # L4_SRC_PORT
				{ 'Length' => 4, 'Id' => 8  }, # IPV4_SRC_ADDR
				{ 'Length' => 4, 'Id' => 10 }, # INPUT_SNMP (Input interface index)
				{ 'Length' => 2, 'Id' => 11 }, # L4_DST_PORT
				{ 'Length' => 4, 'Id' => 12 }, # IPV4_DST_ADDR
				{ 'Length' => 4, 'Id' => 14 }, # OUTPUT_SNMP (Output interface index)
				{ 'Length' => 4, 'Id' => 21 }, # LAST_SWITCHED (System uptime in milliseconds when the last packet of this flow was switched.)
				{ 'Length' => 4, 'Id' => 22 }, # FIRST_SWITCHED (System uptime in milliseconds when the first packet of this flow was switched.)
				{ 'Length' => 2, 'Id' => 32 }, # ICMP_TYPE
				{ 'Length' => 1, 'Id' => 61 }, # DIRECTION (0 = ingress, 1 = egress)
				{ 'Length' => 8, 'Id' => 148 }, # FLOWID (An identifier of a flow that is unique within an observation domain. )
				{ 'Length' => 1, 'Id' => 233 }, # FIREWALLEVENT (0 = Ignore (invalid) 1 = Flow created, 2 = Flow deleted, 3 = Flow denied, 4 = Flow alert, 5 = Flow update)
				],
} ;

my $PATemplateId257={
	'SetId'        =>0,
	'TemplateId'   =>257,
	'Template'=>[
				{ 'Length' => 8, 'Id' => 1  }, # IN_BYTES
				{ 'Length' => 4, 'Id' => 2  }, # IN_PKTS
				{ 'Length' => 1, 'Id' => 4  }, # PROTOCOL
				{ 'Length' => 1, 'Id' => 5  }, # TOS
				{ 'Length' => 1, 'Id' => 6  }, # TCP_FLAGS
				{ 'Length' => 2, 'Id' => 7  }, # L4_SRC_PORT
				{ 'Length' => 4, 'Id' => 8  }, # IPV4_SRC_ADDR
				{ 'Length' => 4, 'Id' => 10 }, # INPUT_SNMP (Input interface index)
				{ 'Length' => 2, 'Id' => 11 }, # L4_DST_PORT
				{ 'Length' => 4, 'Id' => 12 }, # IPV4_DST_ADDR
				{ 'Length' => 4, 'Id' => 14 }, # OUTPUT_SNMP (Output interface index)
				{ 'Length' => 4, 'Id' => 21 }, # LAST_SWITCHED (System uptime in milliseconds when the last packet of this flow was switched.)
				{ 'Length' => 4, 'Id' => 22 }, # FIRST_SWITCHED (System uptime in milliseconds when the first packet of this flow was switched.)
				{ 'Length' => 2, 'Id' => 32 }, # ICMP_TYPE
				{ 'Length' => 1, 'Id' => 61 }, # DIRECTION (0 = ingress, 1 = egress)
				{ 'Length' => 8, 'Id' => 148 }, # flowId (An identifier of a flow that is unique within an observation domain. )
				{ 'Length' => 1, 'Id' => 233 }, # firewallEvent (0 = Ignore (invalid) 1 = Flow created, 2 = Flow deleted, 3 = Flow denied, 4 = Flow alert, 5 = Flow update)
				{ 'Length' => 2, 'Id' => 346 }, # privateEnterpriseNumber (Palo Alto Networks: 25461)
				{ 'Length' => 32, 'Id' => 56701 }, # App-ID
				{ 'Length' => 64, 'Id' => 56702 }, # User-ID
				],
} ;

my $PATemplateId258={
	'SetId'        =>0,
	'TemplateId'   =>258,
	'Template'=>[
				{ 'Length' => 8, 'Id' => 1  }, # IN_BYTES
				{ 'Length' => 4, 'Id' => 2  }, # IN_PKTS
				{ 'Length' => 1, 'Id' => 4  }, # PROTOCOL
				{ 'Length' => 1, 'Id' => 5  }, # TOS
				{ 'Length' => 1, 'Id' => 6  }, # TCP_FLAGS
				{ 'Length' => 2, 'Id' => 7  }, # L4_SRC_PORT
				{ 'Length' => 16, 'Id' => 27 }, # IPV6_SRC_ADDR
				{ 'Length' => 4, 'Id' => 10 }, # INPUT_SNMP (Input interface index)
				{ 'Length' => 2, 'Id' => 11 }, # L4_DST_PORT
				{ 'Length' => 16, 'Id' => 28 }, # IPV6_DST_ADDR
				{ 'Length' => 4, 'Id' => 14 }, # OUTPUT_SNMP (Output interface index)
				{ 'Length' => 4, 'Id' => 21 }, # LAST_SWITCHED (System uptime in milliseconds when the last packet of this flow was switched.)
				{ 'Length' => 4, 'Id' => 22 }, # FIRST_SWITCHED (System uptime in milliseconds when the first packet of this flow was switched.)
				{ 'Length' => 2, 'Id' => 32 }, # ICMP_TYPE
				{ 'Length' => 1, 'Id' => 61 }, # DIRECTION (0 = ingress, 1 = egress)
				{ 'Length' => 8, 'Id' => 148 }, # flowId (An identifier of a flow that is unique within an observation domain. )
				{ 'Length' => 1, 'Id' => 233 }, # firewallEvent (0 = Ignore (invalid) 1 = Flow created, 2 = Flow deleted, 3 = Flow denied, 4 = Flow alert, 5 = Flow update)
				],
} ;

my $PATemplateId259={
	'SetId'        =>0,
	'TemplateId'   =>259,
	'Template'=>[
				{ 'Length' => 8, 'Id' => 1  }, # IN_BYTES
				{ 'Length' => 4, 'Id' => 2  }, # IN_PKTS
				{ 'Length' => 1, 'Id' => 4  }, # PROTOCOL
				{ 'Length' => 1, 'Id' => 5  }, # TOS
				{ 'Length' => 1, 'Id' => 6  }, # TCP_FLAGS
				{ 'Length' => 2, 'Id' => 7  }, # L4_SRC_PORT
				{ 'Length' => 16, 'Id' => 27 }, # IPV6_SRC_ADDR
				{ 'Length' => 4, 'Id' => 10 }, # INPUT_SNMP (Input interface index)
				{ 'Length' => 2, 'Id' => 11 }, # L4_DST_PORT
				{ 'Length' => 16, 'Id' => 28 }, # IPV6_DST_ADDR
				{ 'Length' => 4, 'Id' => 14 }, # OUTPUT_SNMP (Output interface index)
				{ 'Length' => 4, 'Id' => 21 }, # LAST_SWITCHED (System uptime in milliseconds when the last packet of this flow was switched.)
				{ 'Length' => 4, 'Id' => 22 }, # FIRST_SWITCHED (System uptime in milliseconds when the first packet of this flow was switched.)
				{ 'Length' => 2, 'Id' => 32 }, # ICMP_TYPE
				{ 'Length' => 1, 'Id' => 61 }, # DIRECTION (0 = ingress, 1 = egress)
				{ 'Length' => 8, 'Id' => 148 }, # flowId (An identifier of a flow that is unique within an observation domain. )
				{ 'Length' => 1, 'Id' => 233 }, # firewallEvent (0 = Ignore (invalid) 1 = Flow created, 2 = Flow deleted, 3 = Flow denied, 4 = Flow alert, 5 = Flow update)
				{ 'Length' => 2, 'Id' => 346 }, # privateEnterpriseNumber (Palo Alto Networks: 25461)
				{ 'Length' => 32, 'Id' => 56701 }, # App-ID
				{ 'Length' => 64, 'Id' => 56702 }, # User-ID
				],
} ;

my $PATemplateId260={
	'SetId'        =>0,
	'TemplateId'   =>260,
	'Template'=>[
				{ 'Length' => 8, 'Id' => 1  }, # IN_BYTES
				{ 'Length' => 4, 'Id' => 2  }, # IN_PKTS
				{ 'Length' => 1, 'Id' => 4  }, # PROTOCOL
				{ 'Length' => 1, 'Id' => 5  }, # TOS
				{ 'Length' => 1, 'Id' => 6  }, # TCP_FLAGS
				{ 'Length' => 2, 'Id' => 7  }, # L4_SRC_PORT
				{ 'Length' => 4, 'Id' => 8  }, # IPV4_SRC_ADDR
				{ 'Length' => 4, 'Id' => 10 }, # INPUT_SNMP (Input interface index)
				{ 'Length' => 2, 'Id' => 11 }, # L4_DST_PORT
				{ 'Length' => 4, 'Id' => 12 }, # IPV4_DST_ADDR
				{ 'Length' => 4, 'Id' => 14 }, # OUTPUT_SNMP (Output interface index)
				{ 'Length' => 4, 'Id' => 21 }, # LAST_SWITCHED (System uptime in milliseconds when the last packet of this flow was switched.)
				{ 'Length' => 4, 'Id' => 22 }, # FIRST_SWITCHED (System uptime in milliseconds when the first packet of this flow was switched.)
				{ 'Length' => 2, 'Id' => 32 }, # ICMP_TYPE
				{ 'Length' => 1, 'Id' => 61 }, # DIRECTION (0 = ingress, 1 = egress)
				{ 'Length' => 8, 'Id' => 148 }, # flowId (An identifier of a flow that is unique within an observation domain. )
				{ 'Length' => 1, 'Id' => 233 }, # firewallEvent (0 = Ignore (invalid) 1 = Flow created, 2 = Flow deleted, 3 = Flow denied, 4 = Flow alert, 5 = Flow update)
				{ 'Length' => 4, 'Id' => 225 }, # postNATSourceIPv4Address
				{ 'Length' => 4, 'Id' => 226 }, # postNATDestinationIPv4Address
				{ 'Length' => 2, 'Id' => 227 }, # postNAPTSourceTransportPort
				{ 'Length' => 2, 'Id' => 228 }, # postNAPTDestinationTransportPort
				],
} ;

my $PATemplateId261={
	'SetId'        =>0,
	'TemplateId'   =>261,
	'Template'=>[
				{ 'Length' => 8, 'Id' => 1  }, # IN_BYTES
				{ 'Length' => 4, 'Id' => 2  }, # IN_PKTS
				{ 'Length' => 1, 'Id' => 4  }, # PROTOCOL
				{ 'Length' => 1, 'Id' => 5  }, # TOS
				{ 'Length' => 1, 'Id' => 6  }, # TCP_FLAGS
				{ 'Length' => 2, 'Id' => 7  }, # L4_SRC_PORT
				{ 'Length' => 4, 'Id' => 8  }, # IPV4_SRC_ADDR
				{ 'Length' => 4, 'Id' => 10 }, # INPUT_SNMP (Input interface index)
				{ 'Length' => 2, 'Id' => 11 }, # L4_DST_PORT
				{ 'Length' => 4, 'Id' => 12 }, # IPV4_DST_ADDR
				{ 'Length' => 4, 'Id' => 14 }, # OUTPUT_SNMP (Output interface index)
				{ 'Length' => 4, 'Id' => 21 }, # LAST_SWITCHED (System uptime in milliseconds when the last packet of this flow was switched.)
				{ 'Length' => 4, 'Id' => 22 }, # FIRST_SWITCHED (System uptime in milliseconds when the first packet of this flow was switched.)
				{ 'Length' => 2, 'Id' => 32 }, # ICMP_TYPE
				{ 'Length' => 1, 'Id' => 61 }, # DIRECTION (0 = ingress, 1 = egress)
				{ 'Length' => 8, 'Id' => 148 }, # flowId (An identifier of a flow that is unique within an observation domain. )
				{ 'Length' => 1, 'Id' => 233 }, # firewallEvent (0 = Ignore (invalid) 1 = Flow created, 2 = Flow deleted, 3 = Flow denied, 4 = Flow alert, 5 = Flow update)
				{ 'Length' => 4, 'Id' => 225 }, # postNATSourceIPv4Address
				{ 'Length' => 4, 'Id' => 226 }, # postNATDestinationIPv4Address
				{ 'Length' => 2, 'Id' => 227 }, # postNAPTSourceTransportPort
				{ 'Length' => 2, 'Id' => 228 }, # postNAPTDestinationTransportPort
				{ 'Length' => 2, 'Id' => 346 }, # privateEnterpriseNumber (Palo Alto Networks: 25461)
				{ 'Length' => 32, 'Id' => 56701 }, # App-ID
				{ 'Length' => 64, 'Id' => 56702 }, # User-ID
				],
} ;

my @AllTemplates = ( $PATemplateId256, $PATemplateId257, $PATemplateId258, $PATemplateId259, $PATemplateId260, $PATemplateId261 ) ;

my $TEMPLATEID;
my $IN_BYTES;
my $IN_PKTS;
my $PROTOCOL; 
my $TOS;
my $TCP_FLAGS;
my $L4_SRC_PORT;
my $IPV4_SRC_ADDR;
my $INPUT_SNMP;
my $L4_DST_PORT;
my $IPV4_DST_ADDR;
my $OUTPUT_SNMP;
my $LAST_SWITCHED;
my $FIRST_SWITCHED;
my $ICMP_TYPE;
my $DIRECTION;
my $FLOWID;
my $FIREWALLEVENT;
my $PRIVATEENTERPRISENUMBER;
my $APPID;
my $USERID;
my $POSTNATSOURCEIPV4ADDRESS;
my $POSTNATDESTINATIONIPV4ADDRESS;
my $POSTNAPTSOURCETRANSPORTPORT;
my $POSTNAPTDESTINATIONTRANSPORTPORT;

my $receive_port		= 2055 ;
my $packet				= undef ;
my $TemplateArrayRef	= undef ;
my $sock				= IO::Socket::INET->new( LocalPort =>$receive_port, Proto => 'udp') ;

# set your database parameters according to your needs

my $databaseName = "DBI:mysql:netflowdb";	# Database name
my $databaseUser = "netflow";				# Database user name
my $databasePw   = "admin1234";				# Database user password
# my $db_host = '127.0.0.1';
# my $db_port = 3306;

my $dbh = DBI->connect($databaseName, $databaseUser, $databasePw) || die "Connect failed: $DBI::errstr\n";

foreach my $table ('flows') {

    if (does_table_exist($dbh, $table)) {
        print "table $table exists\n";
    }
    else {
        print "table $table does not exist, I create it...\n";
		initializetable(1);	
    }
}

print "Waiting for Palo Alto NetFlow V9 flows on udp port $receive_port...\n";

while ($sock->recv($packet,1548)) {

	my ($HeaderHashRef,$FlowArrayRef,$ErrorsArrayRef)=() ;

	(	$HeaderHashRef,
		$TemplateArrayRef,
		$FlowArrayRef,
		$ErrorsArrayRef)
		= Net::Flow::decode(
							\$packet,
							\@AllTemplates
							#$TemplateArrayRef
							) ;

	grep{ print "$_\n" }@{$ErrorsArrayRef} if( @{$ErrorsArrayRef} ) ;

#	print "\n- Header Information -\n" ;
#	foreach my $Key ( sort keys %{$HeaderHashRef} ){
#		printf " %s = %3d\n",$Key,$HeaderHashRef->{$Key} ;
#	}
#
#	foreach my $TemplateRef ( @{$TemplateArrayRef} ){
#		print "\n-- Template Information --\n" ;
#
#		foreach my $TempKey ( sort keys %{$TemplateRef} ){
#			if( $TempKey eq "Template" ){
#				printf "  %s = \n",$TempKey ;
#				foreach my $Ref ( @{$TemplateRef->{Template}}  ){
#					foreach my $Key ( keys %{$Ref} ){
#						printf "   %s=%s", $Key, $Ref->{$Key} ;
#					}
#					print "\n" ;
#				}
#			}
#			else {
#				printf "  %s = %s\n", $TempKey, $TemplateRef->{$TempKey} ;
#			}
#		}
#	}

	foreach my $FlowRef ( @{$FlowArrayRef} ){
		#print "\n-- Flow Information --\n" ;

		foreach my $Id ( sort keys %{$FlowRef} ){
			if( $Id eq "SetId" ){
				#print "  $Id=$FlowRef->{$Id}\n" if defined $FlowRef->{$Id} ;
				$TEMPLATEID = $FlowRef->{$Id};
			}
			elsif ( ref $FlowRef->{$Id} ) {
				printf "  Id=%s Value=",$Id ;
				foreach my $Value ( @{$FlowRef->{$Id}} ){
					printf "%s,",unpack("H*",$Value) ;
				}
				print "\n" ;
				}
			else {
				#my $hex = unpack("H*",$FlowRef->{$Id});
				#$hex =~ s/0+$//;
				#printf "  Id=%s Value=%s\n",$Id,hex($hex) ;
				# for IP Adress: http://www.coolcommands.com/index.php?option=com_cccat&task=display&id=308
				#printf "  Id=%s Value=%s\n",$Id,unpack("H*",$FlowRef->{$Id}) ;
				
				my $t = time;
				my $Timestamp = strftime "%Y-%m-%d %H:%M:%S", localtime $t;
				$Timestamp .= sprintf "-%03d", ($t-int($t))*1000; # without rounding
				if ( $Id == 1 ) {$IN_BYTES = unpack("x4 N4",$FlowRef->{$Id})}
				elsif ($Id == 2) {$IN_PKTS = unpack("N4",$FlowRef->{$Id})}
				elsif ($Id == 4) {$PROTOCOL = unpack("C2",$FlowRef->{$Id})}
				elsif ($Id == 5) {$TOS = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 6) {$TCP_FLAGS = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 7) {$L4_SRC_PORT = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 8) {$IPV4_SRC_ADDR = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 10) {$INPUT_SNMP = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 11) {$L4_DST_PORT = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 12) {$IPV4_DST_ADDR = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 14) {$OUTPUT_SNMP = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 21) {$LAST_SWITCHED = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 22) {$FIRST_SWITCHED = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 32) {$ICMP_TYPE = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 61) {$DIRECTION = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 148) {$FLOWID = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 233) {$FIREWALLEVENT = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 225) {$POSTNATSOURCEIPV4ADDRESS = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 226) {$POSTNATDESTINATIONIPV4ADDRESS = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 227) {$POSTNAPTSOURCETRANSPORTPORT = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 228) {$POSTNAPTDESTINATIONTRANSPORTPORT = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 346) {$PRIVATEENTERPRISENUMBER = unpack("H*",$FlowRef->{$Id})}
				elsif ($Id == 56701) {$APPID = unpack("x2 a*",$FlowRef->{$Id})}
				elsif ($Id == 56702) {$USERID = unpack("H*",$FlowRef->{$Id})}
				else {
					printf "unknown Id=%s Value=%s\n",$Id,unpack("H*",$FlowRef->{$Id}) ;
				}
				
				my $sql = "INSERT INTO flows (TIMESTAMP, IN_BYTES, IN_PKTS, PROTOCOL, TOS, TCP_FLAGS, L4_SRC_PORT, IPV4_SRC_ADDR, ".
				"INPUT_SNMP, L4_DST_PORT, OUTPUT_SNMP, LAST_SWITCHED, FIRST_SWITCHED, ICMP_TYPE, DIRECTION, FLOWID, FIREWALLEVENT, POSTNATSOURCEIPV4ADDRESS, ".
				"POSTNATDESTINATIONIPV4ADDRESS, POSTNAPTSOURCETRANSPORTPORT, POSTNAPTDESTINATIONTRANSPORTPORT, PRIVATEENTERPRISENUMBER, APPID, USERID, TEMPLATEID) ".
				"VALUES ('$Timestamp', '$IN_BYTES', '$IN_PKTS', '$PROTOCOL', '$TOS', '$TCP_FLAGS', '$L4_SRC_PORT', '$IPV4_SRC_ADDR', '$INPUT_SNMP', '$L4_DST_PORT', ".
				"'$OUTPUT_SNMP', '$LAST_SWITCHED', '$FIRST_SWITCHED', '$ICMP_TYPE', '$DIRECTION', '$FLOWID', '$FIREWALLEVENT', '$POSTNATSOURCEIPV4ADDRESS', ".
				"'$POSTNATDESTINATIONIPV4ADDRESS', '$POSTNAPTSOURCETRANSPORTPORT', '$POSTNAPTDESTINATIONTRANSPORTPORT', '$PRIVATEENTERPRISENUMBER', '$APPID', '$USERID', '$TEMPLATEID')";

				 $dbh->do($sql);
				}
		}
	}
}

# Table Checker
###############

sub does_table_exist {
    my ($dbh,$table_name) = @_;

    my $sth = $dbh->table_info(undef, 'netflowdb', $table_name, 'TABLE');

    $sth->execute;
    my @info = $sth->fetchrow_array;

    my $exists = scalar @info;
    return $exists;
}

# Create Table
###############

sub initializetable {
    my $mode = shift(@_);
    if($mode==1) {						# create table
	    my $query = "CREATE TABLE flows (
							 TIMESTAMP timestamp NOT NULL,
							 TEMPLATEID tinyint(4) NOT NULL default '0',
							 IN_BYTES int NOT NULL default '0',
							 IN_PKTS int NOT NULL default '0',
							 PROTOCOL varchar(2) NOT NULL default '0',
							 TOS varchar(2) NOT NULL default '0',
							 TCP_FLAGS varchar(2) NOT NULL default '0',
							 L4_SRC_PORT varchar(4) NOT NULL default '0',
							 IPV4_SRC_ADDR varchar(8) NOT NULL default '0',
							 INPUT_SNMP varchar(8) NOT NULL default '0',
							 L4_DST_PORT varchar(4) NOT NULL default '0',
							 IPV4_DST_ADDR varchar(8) NOT NULL default '0',
							 OUTPUT_SNMP varchar(8) NOT NULL default '0',
							 LAST_SWITCHED varchar(8) NOT NULL default '0',
							 FIRST_SWITCHED varchar(8) NOT NULL default '0',
							 ICMP_TYPE varchar(4) NOT NULL default '0',
							 DIRECTION varchar(2) NOT NULL default '0',
							 FLOWID varchar(8) NOT NULL default '0',
							 FIREWALLEVENT varchar(2) NOT NULL default '0',
							 PRIVATEENTERPRISENUMBER varchar(4) NOT NULL default '0',
							 APPID varchar(32) NOT NULL default '0',
							 USERID varchar(128) NOT NULL default '0',
							 POSTNATSOURCEIPV4ADDRESS varchar(8) NOT NULL default '0',
							 POSTNATDESTINATIONIPV4ADDRESS varchar(8) NOT NULL default '0',
							 POSTNAPTSOURCETRANSPORTPORT varchar(4) NOT NULL default '0',
							 POSTNAPTDESTINATIONTRANSPORTPORT varchar(4) NOT NULL default '0'
							) ENGINE=MyISAM;";
							 # primary key is an index over the ip fields which should make the update queries for each incoming flow much faster
							 # because it massively speeds up searching for the dataset specified in the WHERE clause
	    $dbh->do($query) or die "Failed to create monthly traffic table.";
    }
	elsif($mode==2) {							# to be defined...
	
	}
}