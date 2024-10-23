/**********************************************************************
 * file:  sr_router.c
 *
 * Descripción:
 *
 * Este archivo contiene todas las funciones que interactúan directamente
 * con la tabla de enrutamiento, así como el método de entrada principal
 * para el enrutamiento.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Inicializa el subsistema de enrutamiento
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    assert(sr);

    /* Inicializa la caché y el hilo de limpieza de la caché */
    sr_arpcache_init(&(sr->cache));

    /* Inicializa los atributos del hilo */
    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    /* Hilo para gestionar el timeout del caché ARP */
    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

} /* -- sr_init -- */

/* Envía un paquete ICMP de error */
void sr_send_icmp_error_packet(uint8_t type,
                              uint8_t code,
                              struct sr_instance *sr,
                              uint32_t ipDst,
                              uint8_t *ipPacket)
{
  
  struct sr_rt* rt_entry=sr->routing_table;

   while(rt_entry!=NULL && (rt_entry->mask.s_addr & ipDst)!=rt_entry->dest.s_addr){

    rt_entry=rt_entry->next;
   }
   struct sr_if* iface=sr_get_interface(sr,rt_entry->interface);
   struct sr_arpentry* entry=sr_arpcache_lookup(&sr->cache,ipDst);
  if(entry!=NULL){
    if(type==3){
    unsigned int icmp_pqtLenght=sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t);
    uint8_t *icmp_Packet = malloc(icmp_pqtLenght);

    sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) icmp_Packet;
    memcpy(ethHdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_dhost, entry->mac, /*sizeof(uint8_t) */ETHER_ADDR_LEN);
    ethHdr->ether_type = htons(ethertype_ip);

    sr_ip_hdr_t *iphdr_icmp= ( sr_ip_hdr_t *)(icmp_Packet+sizeof(sr_ethernet_hdr_t));
    iphdr_icmp->ip_src=iface->ip;
    iphdr_icmp->ip_dst=ipDst;
    iphdr_icmp->ip_ttl=64;/*numero que usa linux*/
    iphdr_icmp->ip_v=4;
    iphdr_icmp->ip_id=0;
    iphdr_icmp->ip_hl=5;
    iphdr_icmp->ip_tos=0;
    iphdr_icmp->ip_len=htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
    iphdr_icmp->ip_off=0;
    iphdr_icmp->ip_p=1;
    iphdr_icmp->ip_sum=0;
    iphdr_icmp->ip_sum=ip_cksum(iphdr_icmp,sizeof(sr_ip_hdr_t));

    sr_icmp_t3_hdr_t *icmp_t3_hdr_ptr = (sr_icmp_t3_hdr_t *)(icmp_Packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    icmp_t3_hdr_ptr->icmp_type = type;            
    icmp_t3_hdr_ptr->icmp_code = code;            
    icmp_t3_hdr_ptr->unused = 0;              
    icmp_t3_hdr_ptr->next_mtu = 0;        
    icmp_t3_hdr_ptr->icmp_sum =0;
    memcpy(icmp_t3_hdr_ptr->data,ipPacket,20);/*copio la cabecera ip*/
    memcpy((icmp_t3_hdr_ptr->data)+20,ipPacket+sizeof(sr_ip_hdr_t), 8);
    icmp_t3_hdr_ptr->icmp_sum = icmp3_cksum(icmp_t3_hdr_ptr,sizeof(sr_icmp_t3_hdr_t));
    print_hdrs(icmp_Packet,icmp_pqtLenght);/*agregue esto*/
    sr_send_packet(sr,icmp_Packet,icmp_pqtLenght,iface->name);
    free(icmp_Packet);
    icmp_Packet=NULL;
    }else if(type==11){

    }else if(type==8){
      
    }
  free(entry);
  }else{
    if(type==3){
    unsigned int icmp_pqtLenght=sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t);
    uint8_t *icmp_Packet = malloc(icmp_pqtLenght);

    sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) icmp_Packet;
    /*memcpy(ethHdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
    memcpy(ethHdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);*/
    ethHdr->ether_type = htons(ethertype_ip);

    sr_ip_hdr_t *iphdr_icmp= ( sr_ip_hdr_t *)(icmp_Packet+sizeof(sr_ethernet_hdr_t));
    iphdr_icmp->ip_src=iface->ip;
    iphdr_icmp->ip_dst=ipDst;
    iphdr_icmp->ip_ttl=64;/*numero que usa linux*/
    iphdr_icmp->ip_v=4;
    iphdr_icmp->ip_id=0;
    iphdr_icmp->ip_hl=5;
    iphdr_icmp->ip_tos=0;
    iphdr_icmp->ip_len=htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
    iphdr_icmp->ip_off=0;
    iphdr_icmp->ip_p=1;
    iphdr_icmp->ip_sum=0;
    iphdr_icmp->ip_sum=ip_cksum(iphdr_icmp,sizeof(sr_ip_hdr_t));

    sr_icmp_t3_hdr_t *icmp_t3_hdr_ptr = (sr_icmp_t3_hdr_t *)(icmp_Packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    icmp_t3_hdr_ptr->icmp_type = type;            
    icmp_t3_hdr_ptr->icmp_code = code;            
    icmp_t3_hdr_ptr->unused = 0;              
    icmp_t3_hdr_ptr->next_mtu = 0;        
    icmp_t3_hdr_ptr->icmp_sum =0;
    memcpy(icmp_t3_hdr_ptr->data,ipPacket,20);/*copio la cabecera ip*/
    memcpy((icmp_t3_hdr_ptr->data)+20,ipPacket+sizeof(sr_ip_hdr_t), 8);
    icmp_t3_hdr_ptr->icmp_sum = icmp3_cksum(icmp_t3_hdr_ptr,sizeof(sr_icmp_t3_hdr_t));
    print_hdrs(icmp_Packet,icmp_pqtLenght);/*agregue esto*/

    struct sr_arpreq* req=sr_arpcache_queuereq(&sr->cache, ipDst, icmp_Packet, icmp_pqtLenght, rt_entry->interface);
      
    handle_arpreq(sr, req);
    }else if(type==11){

    }else if(type==8){
      
    }
    
  }
  
  /* COLOQUE AQUÍ SU CÓDIGO*/

} /* -- sr_send_icmp_error_packet -- */

void sr_handle_ip_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {


  printf("*** -> It is an IP packet. Print IP header.\n");
  print_hdr_ip(packet + sizeof(sr_ethernet_hdr_t));

  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));


  /* Obtengo las direcciones IP */
  uint32_t senderIP = iphdr->ip_src;
  uint32_t targetIP = iphdr->ip_dst;
  

  struct sr_if *myInterface = sr_get_interface_given_ip(sr, targetIP);
  
  if(myInterface==0){/*hay que reenviar*/

   struct sr_rt* rt_entry=sr->routing_table;
   while(rt_entry!=NULL && (rt_entry->mask.s_addr & targetIP)!=rt_entry->dest.s_addr){

    rt_entry=rt_entry->next;
   }
   if(rt_entry!=NULL){/*SI ENCONTRE PREFIJO TENGO QUE REENVIAR*/
      /*tengo la interfaz de salida del datagrama en iter*/
      /*Disminuir el ttl*/
      iphdr->ip_ttl-= 1;
      /*controlar ttl == 0*/
      if (iphdr->ip_ttl == 0){
        /*responder icmp time exceed*/
      } else {
        sr_ethernet_hdr_t *ethHdr=(struct sr_ethernet_hdr *)packet;
        struct sr_if* iface=sr_get_interface(sr,rt_entry->interface);
        /*volver a calcular el checksum */
        iphdr->ip_sum=0;
        iphdr->ip_sum=ip_cksum(iphdr, sizeof(sr_ip_hdr_t)); 
        /*Conseguir interfaz de salida*/
        struct sr_arpentry* entry=sr_arpcache_lookup(&sr->cache,targetIP); /* liberar */
        print_hdrs(packet,len);
        if (entry != NULL) { /*si está en la cache*/
          /*reenviarlo al siguiente salto*/
          printf("ESTA EN CACHE, REENVIO\n");
          memcpy(ethHdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
          memcpy(ethHdr->ether_dhost, entry->mac, /*sizeof(uint8_t) */ETHER_ADDR_LEN);
          ethHdr->ether_type = htons(ethertype_ip);  
          
          sr_send_packet(sr,packet,len,rt_entry->interface);
          free(entry);
        } else { /*si no está*/
          printf("NO ESTA EN CACHE, ARP REQUEST\n");
          /*agrego el paquete a la cola de hasta que se resuelva el
          ARP y obtengo el request*/
          struct sr_arpreq* req=sr_arpcache_queuereq(&sr->cache, targetIP, packet, len, rt_entry->interface);
          /* paso el request a la función que decide cuando se debe
          enviar */
          handle_arpreq(sr, req);
        }
      }
      
    }else{/*SINO MANDAR ICMP NET UNRACHABLE*/
      /*unsigned int icmp_pqtLenght=sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t);
      uint8_t *icmp_Packet = malloc(icmp_pqtLenght);

      sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) icmp_Packet;
      memcpy(ethHdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(ethHdr->ether_dhost, srcAddr, ETHER_ADDR_LEN);
      ethHdr->ether_type = htons(ethertype_ip);


      sr_ip_hdr_t *iphdr_icmp= ( sr_ip_hdr_t *)(icmp_Packet+sizeof(sr_ethernet_hdr_t));
      iphdr_icmp->ip_src=myInterface->ip;
      iphdr_icmp->ip_dst=senderIP;
      iphdr_icmp->ip_ttl=64;
      iphdr_icmp->ip_v=4;
      iphdr_icmp->ip_id=0;
      iphdr_icmp->ip_hl=5;
      iphdr_icmp->ip_tos=0;
      iphdr_icmp->ip_len=htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
      iphdr_icmp->ip_off=0;
      iphdr_icmp->ip_p=1;
      iphdr_icmp->ip_sum=0;
      iphdr_icmp->ip_sum=ip_cksum(iphdr_icmp,sizeof(sr_ip_hdr_t));

      
      sr_icmp_t3_hdr_t *icmp_t3_hdr_ptr = (sr_icmp_t3_hdr_t *)(icmp_Packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
      icmp_t3_hdr_ptr->icmp_type = 3;            
      icmp_t3_hdr_ptr->icmp_code = 0;            
      icmp_t3_hdr_ptr->unused = 0;              
      icmp_t3_hdr_ptr->next_mtu = 0;        
      icmp_t3_hdr_ptr->icmp_sum =0;

      memcpy(icmp_t3_hdr_ptr->data,packet+sizeof(sr_ethernet_hdr_t),20);
      memcpy((icmp_t3_hdr_ptr->data)+20,packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), 8);
      
      icmp_t3_hdr_ptr->icmp_sum = icmp3_cksum(icmp_t3_hdr_ptr,sizeof(sr_icmp_t3_hdr_t));
      print_hdrs(icmp_Packet,icmp_pqtLenght);
      sr_send_packet(sr,icmp_Packet,icmp_pqtLenght,myInterface->name);
      free(icmp_Packet);
      icmp_Packet=NULL;*/
      sr_send_icmp_error_packet(3,0,sr,senderIP,packet+sizeof(sr_ethernet_hdr_t));

   }


  }else{/*es para mi*/
    if(iphdr->ip_p==1){/*paquete ICMP*/
      sr_icmp_hdr_t *icmp_hdr=(sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
      /*El paquete ya es valido no es necesario chequear cheksum*/
      if(icmp_hdr->icmp_type==8){ /* si es echo request respondo echo reply*/
        sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) packet;
        memcpy(ethHdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
        memcpy(ethHdr->ether_dhost, srcAddr, /*sizeof(uint8_t) */ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_ip);
        uint32_t destino=iphdr->ip_src;
        iphdr->ip_src=myInterface->ip;
        iphdr->ip_dst=destino;
        iphdr->ip_sum=0;
        iphdr->ip_sum=ip_cksum(iphdr,sizeof(sr_ip_hdr_t));
        iphdr->ip_ttl=64;
        icmp_hdr->icmp_type=0;
        icmp_hdr->icmp_sum=0;
        icmp_hdr->icmp_sum= cksum(icmp_hdr,len-sizeof(sr_ip_hdr_t)-sizeof(sr_ethernet_hdr_t));
        print_hdrs(packet,len);
        sr_send_packet(sr,packet,len,myInterface->name);

      }

    }else if(iphdr->ip_p==6 || iphdr->ip_p==17){ /* Si es tcp o udp respondo port unrecheable*/

      /*unsigned int icmp_pqtLenght=sizeof(sr_icmp_t3_hdr_t)+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t);
      uint8_t *icmp_Packet = malloc(icmp_pqtLenght);

      sr_ethernet_hdr_t *ethHdr = (struct sr_ethernet_hdr *) icmp_Packet;
      memcpy(ethHdr->ether_shost, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(ethHdr->ether_dhost, srcAddr, ETHER_ADDR_LEN); 
      ethHdr->ether_type = htons(ethertype_ip);


      sr_ip_hdr_t *iphdr_icmp= ( sr_ip_hdr_t *)(icmp_Packet+sizeof(sr_ethernet_hdr_t));
      iphdr_icmp->ip_src=myInterface->ip;
      iphdr_icmp->ip_dst=senderIP;
      iphdr_icmp->ip_ttl=64;
      iphdr_icmp->ip_v=4;
      iphdr_icmp->ip_id=0;
      iphdr_icmp->ip_hl=5;
      iphdr_icmp->ip_tos=0;
      iphdr_icmp->ip_len=htons(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
      iphdr_icmp->ip_off=0;
      iphdr_icmp->ip_p=1;
      iphdr_icmp->ip_sum=0;
      iphdr_icmp->ip_sum=ip_cksum(iphdr_icmp,sizeof(sr_ip_hdr_t));

      
      sr_icmp_t3_hdr_t *icmp_t3_hdr_ptr = (sr_icmp_t3_hdr_t *)(icmp_Packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
      icmp_t3_hdr_ptr->icmp_type = 3;            
      icmp_t3_hdr_ptr->icmp_code = 3;            
      icmp_t3_hdr_ptr->unused = 0;              
      icmp_t3_hdr_ptr->next_mtu = 0;        
      icmp_t3_hdr_ptr->icmp_sum =0;

      memcpy(icmp_t3_hdr_ptr->data,packet+sizeof(sr_ethernet_hdr_t),20);
      memcpy((icmp_t3_hdr_ptr->data)+20,packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t), 8);
      
      icmp_t3_hdr_ptr->icmp_sum = icmp3_cksum(icmp_t3_hdr_ptr,sizeof(sr_icmp_t3_hdr_t));
      print_hdrs(icmp_Packet,icmp_pqtLenght);
      sr_send_packet(sr,icmp_Packet,icmp_pqtLenght,myInterface->name);
      free(icmp_Packet);
      icmp_Packet=NULL;*/
      sr_send_icmp_error_packet(3,3,sr,senderIP,packet+sizeof(sr_ethernet_hdr_t));
    }
    else{
      /*??????????*/
    }

  }
  /* 
  * COLOQUE ASÍ SU CÓDIGO
  * SUGERENCIAS: 
  * - Obtener el cabezal IP y direcciones 
  * - Verificar si el paquete es para una de mis interfaces o si hay una coincidencia en mi tabla de enrutamiento 
  * - Si no es para una de mis interfaces y no hay coincidencia en la tabla de enrutamiento, enviar ICMP net unreachable
  * - Sino, si es para mí, verificar si es un paquete ICMP echo request y responder con un echo reply 
  * - Sino, verificar TTL, ARP y reenviar si corresponde (puede necesitar una solicitud ARP y esperar la respuesta)
  * - No olvide imprimir los mensajes de depuración
  */

}

/* 
* ***** A partir de aquí no debería tener que modificar nada ****
*/

/* Envía todos los paquetes IP pendientes de una solicitud ARP */
void sr_arp_reply_send_pending_packets(struct sr_instance *sr,
                                        struct sr_arpreq *arpReq,
                                        uint8_t *dhost,
                                        uint8_t *shost,
                                        struct sr_if *iface) {

  struct sr_packet *currPacket = arpReq->packets;
  sr_ethernet_hdr_t *ethHdr;
  uint8_t *copyPacket;

  while (currPacket != NULL) {
     ethHdr = (sr_ethernet_hdr_t *) currPacket->buf;
     memcpy(ethHdr->ether_shost, dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
     memcpy(ethHdr->ether_dhost, shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

     copyPacket = malloc(sizeof(uint8_t) * currPacket->len);
     memcpy(copyPacket, ethHdr, sizeof(uint8_t) * currPacket->len);

     print_hdrs(copyPacket, currPacket->len);
     sr_send_packet(sr, copyPacket, currPacket->len, iface->name);
     currPacket = currPacket->next;
  }
}

/* Gestiona la llegada de un paquete ARP*/
void sr_handle_arp_packet(struct sr_instance *sr,
        uint8_t *packet /* lent */,
        unsigned int len,
        uint8_t *srcAddr,
        uint8_t *destAddr,
        char *interface /* lent */,
        sr_ethernet_hdr_t *eHdr) {

  /* Imprimo el cabezal ARP */
  printf("*** -> It is an ARP packet. Print ARP header.\n");
  print_hdr_arp(packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo el cabezal ARP */
  sr_arp_hdr_t *arpHdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

  /* Obtengo las direcciones MAC */
  unsigned char senderHardAddr[ETHER_ADDR_LEN], targetHardAddr[ETHER_ADDR_LEN];
  memcpy(senderHardAddr, arpHdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(targetHardAddr, arpHdr->ar_tha, ETHER_ADDR_LEN);

  /* Obtengo las direcciones IP */
  uint32_t senderIP = arpHdr->ar_sip;
  uint32_t targetIP = arpHdr->ar_tip;
  unsigned short op = ntohs(arpHdr->ar_op);

  /* Verifico si el paquete ARP es para una de mis interfaces */
  struct sr_if *myInterface = sr_get_interface_given_ip(sr, targetIP);

  if (op == arp_op_request) {  /* Si es un request ARP */
    printf("**** -> It is an ARP request.\n");

    /* Si el ARP request es para una de mis interfaces */
    if (myInterface != 0) {
      printf("***** -> ARP request is for one of my interfaces.\n");

      /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
      printf("****** -> Add MAC->IP mapping of sender to my ARP cache.\n");
      sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);

      /* Construyo un ARP reply y lo envío de vuelta */
      printf("****** -> Construct an ARP reply and send it back.\n");
      memcpy(eHdr->ether_shost, (uint8_t *) myInterface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(eHdr->ether_dhost, (uint8_t *) senderHardAddr, sizeof(uint8_t) * ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_sha, myInterface->addr, ETHER_ADDR_LEN);
      memcpy(arpHdr->ar_tha, senderHardAddr, ETHER_ADDR_LEN);
      arpHdr->ar_sip = targetIP;
      arpHdr->ar_tip = senderIP;
      arpHdr->ar_op = htons(arp_op_reply);

      /* Imprimo el cabezal del ARP reply creado */
      print_hdrs(packet, len);

      sr_send_packet(sr, packet, len, myInterface->name);
    }

    printf("******* -> ARP request processing complete.\n");

  } else if (op == arp_op_reply) {  /* Si es un reply ARP */

    printf("**** -> It is an ARP reply.\n");

    /* Agrego el mapeo MAC->IP del sender a mi caché ARP */
    printf("***** -> Add MAC->IP mapping of sender to my ARP cache.\n");
    struct sr_arpreq *arpReq = sr_arpcache_insert(&(sr->cache), senderHardAddr, senderIP);
    
    if (arpReq != NULL) { /* Si hay paquetes pendientes */

    	printf("****** -> Send outstanding packets.\n");
    	sr_arp_reply_send_pending_packets(sr, arpReq, (uint8_t *) myInterface->addr, (uint8_t *) senderHardAddr, myInterface);
    	sr_arpreq_destroy(&(sr->cache), arpReq);

    }
    printf("******* -> ARP reply processing complete.\n");
  }
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* Obtengo direcciones MAC origen y destino */
  sr_ethernet_hdr_t *eHdr = (sr_ethernet_hdr_t *) packet;
  uint8_t *destAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *srcAddr = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(destAddr, eHdr->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(srcAddr, eHdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t pktType = ntohs(eHdr->ether_type);

  if (is_packet_valid(packet, len)) {
    if (pktType == ethertype_arp) {
      sr_handle_arp_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    } else if (pktType == ethertype_ip) {
      sr_handle_ip_packet(sr, packet, len, srcAddr, destAddr, interface, eHdr);
    }
  }

}/* end sr_ForwardPacket */