/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
const bit<16> ETHERTYPE_TPID = 0x8100;
const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<8>  TYPE_TCP       = 0x06;
const bit<8>  TYPE_UDP       = 0x11;


const int CPU_PORT = 64;

/* Table Sizes */
/* 
 * We use C preprocessor here so that we can easily overwrite
 * these constants from the command line
 */
#ifndef IPV4_HOST_SIZE
  #define IPV4_HOST_SIZE 65536
#endif

#ifndef IPV4_LPM_SIZE 
  #define IPV4_LPM_SIZE 12288
#endif

const int IPV4_HOST_TABLE_SIZE = IPV4_HOST_SIZE;
const int IPV4_LPM_TABLE_SIZE  = IPV4_LPM_SIZE;

struct pair {
    bit<32>     key;
    bit<32>     count;
}

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   dei;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header tcp_h{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_h{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h   ethernet;
    vlan_tag_h   vlan_tag;
    ipv4_h       ipv4;
    tcp_h        tcp;
    udp_h        udp;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    pair carrier_1;
    pair carrier_2;
    pair carrier_3;
    pair carrier_4;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            ETHERTYPE_TPID:  parse_vlan_tag;
            default: accept;
        }
    }
    
    state parse_vlan_tag {
        pkt.extract(hdr.vlan_tag);
        transition select(hdr.vlan_tag.ether_type) {
            ETHERTYPE_IPV4:  parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_TCP: parse_tcp;
            TYPE_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{
//Hash custom table
    CRCPolynomial<bit<32>>(32w0x04C11DB7, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly1;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM, poly1) hash1;

    CRCPolynomial<bit<32>>(32w0x2F5EACD3, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly2;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM, poly2) hash2;

    CRCPolynomial<bit<32>>(32w0x7B1F892A, // polynomial
                           true,          // reversed
                           false,         // use msb?
                           false,         // extended?
                           32w0xFFFFFFFF, // initial shift register value
                           32w0xFFFFFFFF  // result xor
                           ) poly3;
    Hash<bit<9>>(HashAlgorithm_t.CUSTOM, poly3) hash3;

// Write RegisterAction
    Register<pair, _>(512) HH_layer_key_1;
    RegisterAction<pair, bit<9>, bit<32>>(HH_layer_key_1) HH_key_1= {
        void apply(inout pair value, out bit<32> newvalue){
            bit<32> tmp = value.key;
            if(meta.carrier_1.key == value.key) {
                value.count = value.count + 1;
                newvalue = 0;
            } else {
                newvalue = tmp;
                value.count = 1;
                value.key = meta.carrier_1.key;
            }
        }
    };
    action key_1(bit<9> reg) {
        meta.carrier_2.key = HH_key_1.execute(reg);
    }
    
    Register<pair, _>(512) HH_layer_count_1;
    RegisterAction<pair, bit<9>, bit<32>>(HH_layer_count_1) HH_count_1= {
        void apply(inout pair value, out bit<32> newvalue){
            bit<32> tmp = value.count;
            if(meta.carrier_1.key == value.key) {
                value.count = value.count + 1;
                newvalue = 0;
            } else {
                newvalue = tmp;
                value.count = 1;
                value.key = meta.carrier_1.key;
            }
        }
    };
    action count_1(bit<9> reg) {
        meta.carrier_2.count = HH_count_1.execute(reg);
    }

    Register<pair, _>(512) HH_layer_key_2;
    RegisterAction<pair, bit<9>, bit<32>>(HH_layer_key_2) HH_key_2= {
        void apply(inout pair value, out bit<32> newvalue){
            bit<32> tmp = value.key;
            if(meta.carrier_2.key == value.key) {
                value.count = value.count + meta.carrier_2.count;
                newvalue = 0;
            } else {
                if(meta.carrier_2.count > value.count){
                    newvalue = tmp;
                    value.key = meta.carrier_2.key;
                    value.count = meta.carrier_2.count;
                } else {
                    newvalue = tmp;
                }
            }
        }
    };
    action key_2(bit<9> reg) {
        meta.carrier_3.key = HH_key_2.execute(reg);
    }
    
    Register<pair, _>(512) HH_layer_count_2;
    RegisterAction<pair, bit<9>, bit<32>>(HH_layer_count_2) HH_count_2= {
        void apply(inout pair value, out bit<32> newvalue){
            bit<32> tmp = value.count;
            if(meta.carrier_2.key == value.key) {
                value.count = value.count + meta.carrier_2.count;
                newvalue = 0;
            } else {
                if(meta.carrier_2.count > value.count){
                    newvalue = tmp;
                    value.key = meta.carrier_2.key;
                    value.count = meta.carrier_2.count;
                } else {
                    newvalue = 0;
                }
            }
        }
    };
    action count_2(bit<9> reg) {
        meta.carrier_3.count = HH_count_2.execute(reg);
    }

    Register<pair, _>(512) HH_layer_key_3;
    RegisterAction<pair, bit<9>, bit<32>>(HH_layer_key_3) HH_key_3= {
        void apply(inout pair value, out bit<32> newvalue){
            bit<32> tmp = value.key;
            if(meta.carrier_3.key == value.key) {
                value.count = value.count + meta.carrier_3.count;
                newvalue = 0;
            } else {
                if(meta.carrier_3.count > value.count){
                    newvalue = tmp;
                    value.key = meta.carrier_3.key;
                    value.count = meta.carrier_3.count;
                } else {
                    newvalue = tmp;
                }
            }
        }
    };
    action key_3(bit<9> reg) {
        meta.carrier_4.key = HH_key_3.execute(reg);
    }
    
    Register<pair, _>(512) HH_layer_count_3;
    RegisterAction<pair, bit<9>, bit<32>>(HH_layer_count_3) HH_count_3= {
        void apply(inout pair value, out bit<32> newvalue){
            bit<32> tmp = value.count;
            if(meta.carrier_3.key == value.key) {
                value.count = value.count + meta.carrier_3.count;
                newvalue = 0;
            } else {
                if(meta.carrier_3.count > value.count){
                    newvalue = tmp;
                    value.key = meta.carrier_3.key;
                    value.count = meta.carrier_3.count;
                } else {
                    newvalue = 0;
                }
            }
        }
    };
    action count_3(bit<9> reg) {
        meta.carrier_4.count = HH_count_3.execute(reg);
    }

    action send(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
        ig_tm_md.qid = 0;
    }

    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    table ipv4_host {
        key = { hdr.ipv4.dst_addr : exact; }
        actions = {
            send; drop;
        }
        size = IPV4_HOST_TABLE_SIZE;
    }

    table ipv4_lpm {
        key     = { hdr.ipv4.dst_addr : lpm; }
        actions = { send; drop; }

        default_action = send(CPU_PORT);
        size           = IPV4_LPM_TABLE_SIZE;
    }

    apply {
        bit<16> in_port = 0;
        bit<16> out_port = 0;
        bit<9> reg_pos_1 = 0;
        bit<9> reg_pos_2 = 0;
        bit<9> reg_pos_3 = 0;

        if(ipv4_host.apply().miss) {
            ipv4_lpm.apply();
        }
        if (hdr.ipv4.isValid()) {
            if(hdr.tcp.isValid()) {
                in_port = hdr.tcp.srcPort;
                out_port = hdr.tcp.dstPort;
            } else {
                in_port = hdr.udp.srcPort;
                out_port = hdr.udp.dstPort;
            }
            // Stage 1
            meta.carrier_1.key[15:0] = in_port;
            meta.carrier_1.key[31:16] = out_port;

            reg_pos_1 = hash1.get({
                in_port,
                out_port,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol
            });
            key_1(reg_pos_1);
            count_1(reg_pos_1);

            // Stage 2
            reg_pos_2 = hash2.get({
                in_port,
                out_port,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol
            });
            key_2(reg_pos_2);
            count_2(reg_pos_2);
            if(meta.carrier_3.key != 0 && meta.carrier_3.count == 0) {
                meta.carrier_3 = meta.carrier_2;
            }
            // Stage 3
            reg_pos_3 = hash3.get({
                in_port,
                out_port,
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol
            });
            key_3(reg_pos_3);
            count_3(reg_pos_3);
        }
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    bit<32> qlen;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {

    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
