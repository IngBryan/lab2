/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 *
 * Descripción:
 * Este archivo contiene las funciones necesarias para el manejo de los paquetes
 * OSPF.
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <malloc.h>

#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "sr_utils.h"
#include "sr_protocol.h"
#include "pwospf_protocol.h"
#include "sr_rt.h"
#include "pwospf_neighbors.h"
#include "pwospf_topology.h"
#include "dijkstra.h"

/*pthread_t hello_thread;*/
pthread_t g_hello_packet_thread;
pthread_t g_all_lsu_thread;
pthread_t g_lsu_thread;
pthread_t g_neighbors_thread;
pthread_t g_topology_entries_thread;
pthread_t g_rx_lsu_thread;
pthread_t g_dijkstra_thread;

pthread_mutex_t g_dijkstra_mutex = PTHREAD_MUTEX_INITIALIZER;

struct in_addr g_router_id;
uint8_t g_ospf_multicast_mac[ETHER_ADDR_LEN];
struct ospfv2_neighbor* g_neighbors;
struct pwospf_topology_entry* g_topology;
uint16_t g_sequence_num;

/* -- Declaración de hilo principal de la función del subsistema pwospf --- */
static void* pwospf_run_thread(void* arg);

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Configura las estructuras de datos internas para el subsistema pwospf
 * y crea un nuevo hilo para el subsistema pwospf.
 *
 * Se puede asumir que las interfaces han sido creadas e inicializadas
 * en este punto.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);

    g_router_id.s_addr = 0;

    /* Defino la MAC de multicast a usar para los paquetes HELLO */
    g_ospf_multicast_mac[0] = 0x01;
    g_ospf_multicast_mac[1] = 0x00;
    g_ospf_multicast_mac[2] = 0x5e;
    g_ospf_multicast_mac[3] = 0x00;
    g_ospf_multicast_mac[4] = 0x00;
    g_ospf_multicast_mac[5] = 0x05;

    g_neighbors = NULL;

    g_sequence_num = 0;


    struct in_addr zero;
    zero.s_addr = 0;
    g_neighbors = create_ospfv2_neighbor(zero);
    g_topology = create_ospfv2_topology_entry(zero, zero, zero, zero, zero, 0);

    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) { 
        perror("pthread_create");
        assert(0);
    }

    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
}

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} 

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Hilo principal del subsistema pwospf.
 *
 *---------------------------------------------------------------------*/

static
void* pwospf_run_thread(void* arg)
{
    sleep(5);

    struct sr_instance* sr = (struct sr_instance*)arg;

    /* Set the ID of the router */
    while(g_router_id.s_addr == 0)
    {
        struct sr_if* int_temp = sr->if_list;
        while(int_temp != NULL)
        {
            if (int_temp->ip > g_router_id.s_addr)
            {
                g_router_id.s_addr = int_temp->ip;
            }

            int_temp = int_temp->next;
        }
    }
    Debug("\n\nPWOSPF: Selecting the highest IP address on a router as the router ID\n");
    Debug("-> PWOSPF: The router ID is [%s]\n", inet_ntoa(g_router_id));


    Debug("\nPWOSPF: Detecting the router interfaces and adding their networks to the routing table\n");
    struct sr_if* int_temp = sr->if_list;
    while(int_temp != NULL)
    {
        struct in_addr ip;
        ip.s_addr = int_temp->ip;
        struct in_addr gw;
        gw.s_addr = 0x00000000;
        struct in_addr mask;
        mask.s_addr =  int_temp->mask;
        struct in_addr network;
        network.s_addr = ip.s_addr & mask.s_addr;

        if (check_route(sr, network) == 0)
        {
            Debug("-> PWOSPF: Adding the directly connected network [%s, ", inet_ntoa(network));
            Debug("%s] to the routing table\n", inet_ntoa(mask));
            sr_add_rt_entry(sr, network, gw, mask, int_temp->name, 1);
        }
        int_temp = int_temp->next;
    }
    
    Debug("\n-> PWOSPF: Printing the forwarding table\n");
    sr_print_routing_table(sr);


    pthread_create(&g_hello_packet_thread, NULL, send_hellos, sr);
    pthread_create(&g_all_lsu_thread, NULL, send_all_lsu, sr);
    pthread_create(&g_neighbors_thread, NULL, check_neighbors_life, sr);
    pthread_create(&g_topology_entries_thread, NULL, check_topology_entries_age, sr);

    return NULL;
} /* -- run_ospf_thread -- */

/***********************************************************************************
 * Métodos para el manejo de los paquetes HELLO y LSU
 * SU CÓDIGO DEBERÍA IR AQUÍ
 * *********************************************************************************/

/*---------------------------------------------------------------------
 * Method: check_neighbors_life
 *
 * Chequea si los vecinos están vivos
 *
 *---------------------------------------------------------------------*/

void* check_neighbors_life(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;
    
    while(1)
    {
        usleep(1000000);
        /*Si hay un cambio, se debe ajustar el neighbor id en la interfaz.*/
        struct ospfv2_neighbor *result=check_neighbors_alive(g_neighbors);
        struct sr_if *aux=sr->if_list;
        while (result!=NULL){
            
            while (aux!=NULL && aux->neighbor_id!=result->neighbor_id.s_addr){
                aux=aux->next;
            }
            if(aux!=NULL){
                aux->neighbor_id=0;
                aux->neighbor_ip=0;
            }
            struct ospfv2_neighbor *resultaux=result;
            result=result->next;
            free(resultaux);

        }
    }
    return NULL;
} /* -- check_neighbors_life -- */


/*---------------------------------------------------------------------
 * Method: check_topology_entries_age
 *
 * Check if the topology entries are alive 
 * and if they are not, remove them from the topology table
 *
 *---------------------------------------------------------------------*/

void* check_topology_entries_age(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while (1)
    {

        usleep(1000000);
        printf("antes del cambio");
        print_topolgy_table(g_topology);
        uint8_t p= check_topology_age(g_topology);
        if (p == 1) {
            dijkstra_param_t dij_param;
            dij_param.sr=sr;
            dij_param.mutex=g_dijkstra_mutex;
            dij_param.rid=g_router_id;
            dij_param.topology=g_topology;

            printf("despues del cambio");
            print_topolgy_table(g_topology);
            pthread_create(&g_dijkstra_thread, NULL, run_dijkstra, &dij_param);
        }else{
            printf("No hubo cambio");
            print_topolgy_table(g_topology);
        }
    /* 
    
    Cada 1 segundo, chequea el tiempo de vida de cada entrada
    de la topologia.
    Si hay un cambio en la topología, se llama a la función de Dijkstra
    en un nuevo hilo.
    Se sugiere también imprimir la topología resultado del chequeo.
    */
    }

    return NULL;
} /* -- check_topology_entries_age -- */


/*---------------------------------------------------------------------
 * Method: send_hellos
 *
 * Para cada interfaz y cada helloint segundos, construye mensaje 
 * HELLO y crea un hilo con la función para enviar el mensaje.
 *
 *---------------------------------------------------------------------*/

void* send_hellos(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    /* While true */
    while(1)
    {
        /* Se ejecuta cada 1 segundo */
        usleep(1000000);

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);
        struct sr_if* aux_iface=sr->if_list;
        while(aux_iface!=NULL){
            powspf_hello_lsu_param_t args;
            args.interface=aux_iface;
            args.sr=sr;
            if(aux_iface->helloint == 0){
                pthread_create(&g_hello_packet_thread, &args, send_hello_packet, sr);
                aux_iface->helloint=OSPF_DEFAULT_HELLOINT;
            }else {
                aux_iface->helloint --;
            }
            aux_iface=aux_iface->next;
        
        }
        /* Chequeo todas las interfaces para enviar el paquete HELLO */
            /* Cada interfaz matiene un contador en segundos para los HELLO*/
            /* Reiniciar el contador de segundos para HELLO */

        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
    };

    return NULL;
} /* -- send_hellos -- */


/*---------------------------------------------------------------------
 * Method: send_hello_packet
 *
 * Recibe un mensaje HELLO, agrega cabezales y lo envía por la interfaz
 * correspondiente.
 *
 *---------------------------------------------------------------------*/

void* send_hello_packet(void* arg)
{
    powspf_hello_lsu_param_t* hello_param = ((powspf_hello_lsu_param_t*)(arg));

    Debug("\n\nPWOSPF: Constructing HELLO packet for interface %s: \n", hello_param->interface->name);
    unsigned int hello_lenght=sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(ospfv2_hdr_t)
                              +sizeof(ospfv2_hello_hdr_t);
    uint8_t * packet_hello=malloc(hello_lenght);
    sr_ethernet_hdr_t * e_hdr=(sr_ethernet_hdr_t *)packet_hello;

    
    memcpy(e_hdr->ether_dhost, g_ospf_multicast_mac, ETHER_ADDR_LEN);
    memcpy(e_hdr->ether_shost,hello_param->interface->addr,ETHER_ADDR_LEN);
    e_hdr->ether_type=htons(ethertype_ip);
    /* Seteo la dirección MAC de multicast para la trama a enviar */
    /* Seteo la dirección MAC origen con la dirección de mi interfaz de salida */
    /* Seteo el ether_type en el cabezal Ethernet */
    sr_ip_hdr_t * ip_hdr=(sr_ip_hdr_t*)(packet_hello+sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_len=htons(sizeof(sr_ip_hdr_t)+sizeof(ospfv2_hdr_t)
                              +sizeof(ospfv2_hello_hdr_t));
    ip_hdr->ip_hl=5;
    ip_hdr->ip_v=4;
    ip_hdr->ip_dst=htonl(OSPF_AllSPFRouters);
    ip_hdr->ip_src=hello_param->interface->ip;
    ip_hdr->ip_p=89;
    ip_hdr->ip_id=0;
    ip_hdr->ip_off=0;
    ip_hdr->ip_tos=0;
    ip_hdr->ip_ttl=64;
    ip_hdr->ip_sum=0;
    ip_hdr->ip_sum=ip_cksum(ip_hdr,sizeof(sr_ip_hdr_t));
    /* Inicializo cabezal IP */
    /* Seteo el protocolo en el cabezal IP para ser el de OSPF (89) */
    /* Seteo IP origen con la IP de mi interfaz de salida */
    /* Seteo IP destino con la IP de Multicast dada: OSPF_AllSPFRouters  */
    /* Calculo y seteo el chechsum IP*/
    ospfv2_hdr_t *p_hdr=(ospfv2_hdr_t*)(packet_hello+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    p_hdr->aid=0;
    p_hdr->rid=g_router_id.s_addr;
    p_hdr->audata=0;
    p_hdr->autype=0;
    p_hdr->version=2;
    p_hdr->type=OSPF_TYPE_HELLO;
    p_hdr->len = htons(sizeof(ospfv2_hdr_t) + sizeof(ospfv2_hello_hdr_t));


    /* Inicializo cabezal de PWOSPF con version 2 y tipo HELLO */
    
    /* Seteo el Router ID con mi ID*/
    /* Seteo el Area ID en 0 */
    /* Seteo el Authentication Type y Authentication Data en 0*/
    ospfv2_hello_hdr_t *hello_hdr=(ospfv2_hello_hdr_t*)(packet_hello+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(ospfv2_hdr_t));
    hello_hdr->padding=0;
    hello_hdr->helloint=htons(OSPF_DEFAULT_HELLOINT);
    hello_hdr->nmask=hello_param->interface->mask;
    p_hdr->csum=0;
    p_hdr->csum=ospfv2_cksum(p_hdr,sizeof(ospfv2_hdr_t)+sizeof(ospfv2_hello_hdr_t));/*Preguntar*/
    /* Seteo máscara con la máscara de mi interfaz de salida */
    /* Seteo Hello Interval con OSPF_DEFAULT_HELLOINT */
    /* Seteo Padding en 0*/

    /* Creo el paquete a transmitir */
    
    /* Calculo y actualizo el checksum del cabezal OSPF */
    sr_send_packet(hello_param->sr,packet_hello,hello_lenght,hello_param->interface->name);
    /* Envío el paquete HELLO */
    /* Imprimo información del paquete HELLO enviado */
    
    Debug("-> PWOSPF: Sending HELLO Packet of length = %d, out of the interface: %s\n", hello_lenght, hello_param->interface->name);
    Debug("      [Router ID = %s]\n", inet_ntoa(g_router_id));
    Debug("      [Router IP = %s]\n", inet_ntoa((struct in_addr ){.s_addr=hello_param->interface->ip}));
    Debug("      [Network Mask = %s]\n", inet_ntoa((struct in_addr){.s_addr=hello_param->interface->mask}));
    free(packet_hello);
    return NULL;
} /* -- send_hello_packet -- */

/*---------------------------------------------------------------------
 * Method: send_all_lsu
 *
 * Construye y envía LSUs cada 30 segundos
 *
 *---------------------------------------------------------------------*/

void* send_all_lsu(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    /* while true*/
    while(1)
    {
        /* Se ejecuta cada OSPF_DEFAULT_LSUINT segundos */
        usleep(OSPF_DEFAULT_LSUINT * 1000000);

        /* Bloqueo para evitar mezclar el envío de HELLOs y LSUs */
        pwospf_lock(sr->ospf_subsys);
        struct sr_if* aux_iface=sr->if_list;
        /* Recorro todas las interfaces para enviar el paquete LSU */
        while(aux_iface!=NULL){
            /* Si la interfaz tiene un vecino, envío un LSU */
            if (aux_iface->neighbor_id != 0){ 
                powspf_hello_lsu_param_t args;
                args.interface=aux_iface;
                args.sr=sr;
                pthread_create(&g_lsu_thread, &args, send_lsu, sr);
            }
            aux_iface = aux_iface->next;
        }
        /* Desbloqueo */
        pwospf_unlock(sr->ospf_subsys);
    };

    return NULL;
} /* -- send_all_lsu -- */

/*---------------------------------------------------------------------
 * Method: send_lsu
 *
 * Construye y envía paquetes LSU a través de una interfaz específica
 *
 *---------------------------------------------------------------------*/

void* send_lsu(void* arg)
{
    powspf_hello_lsu_param_t* lsu_param = ((powspf_hello_lsu_param_t*)(arg));

    /* Solo envío LSUs si del otro lado hay un router*/
    
    /* Construyo el LSU */
    Debug("\n\nPWOSPF: Constructing LSU packet\n");
    int routes_count = count_routes(lsu_param->sr);
    unsigned int lsu_lenght=sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(ospfv2_hdr_t)
                              +sizeof(ospfv2_lsu_hdr_t)+routes_count*sizeof(ospfv2_lsa_t);
    /* Creo el paquete y seteo todos los cabezales del paquete a transmitir */
    uint8_t * packet_lsu=malloc(lsu_lenght);
    /* Inicializo cabezal Ethernet */
    sr_ethernet_hdr_t * e_hdr=(sr_ethernet_hdr_t *)packet_lsu;
    e_hdr->ether_type=htons(ethertype_ip);
    memcpy(e_hdr->ether_shost,lsu_param->interface->addr,ETHER_ADDR_LEN);
    /* Dirección MAC destino la dejo para el final ya que hay que hacer ARP */
    
    /* Inicializo cabezal IP*/
    sr_ip_hdr_t * ip_hdr=(sr_ip_hdr_t*)(packet_lsu+sizeof(sr_ethernet_hdr_t));
    ip_hdr->ip_len=htons(sizeof(sr_ip_hdr_t)+sizeof(ospfv2_hdr_t)
                              +sizeof(ospfv2_lsu_hdr_t)+routes_count*sizeof(ospfv2_lsa_t));
    
    /* La IP destino es la del vecino contectado a mi interfaz*/
    ip_hdr->ip_dst=lsu_param->interface->neighbor_ip;
    ip_hdr->ip_hl=5; 
    ip_hdr->ip_v=4;
    ip_hdr->ip_src=lsu_param->interface->ip;
    ip_hdr->ip_p=89;
    ip_hdr->ip_id=0;
    ip_hdr->ip_off=0;
    ip_hdr->ip_tos=0;
    ip_hdr->ip_ttl=64;
    ip_hdr->ip_sum=0;
    ip_hdr->ip_sum=ip_cksum(ip_hdr,sizeof(sr_ip_hdr_t));
    
    /* Inicializo cabezal de OSPF*/
    ospfv2_hdr_t *p_hdr=(ospfv2_hdr_t*)(packet_lsu+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    p_hdr->rid=g_router_id.s_addr;
    p_hdr->aid=0;
    p_hdr->audata=0;
    p_hdr->autype=0;
    p_hdr->version=2;
    p_hdr->type=OSPF_TYPE_LSU;
    p_hdr->len=htons(sizeof(ospfv2_hdr_t)+sizeof(ospfv2_lsu_hdr_t)+routes_count*sizeof(ospfv2_lsa_t));
    
    ospfv2_lsu_hdr_t *lsu_hdr=(ospfv2_lsu_hdr_t*)(packet_lsu+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(ospfv2_hdr_t));
    /* Seteo el número de secuencia y avanzo*/
    lsu_hdr->seq=g_sequence_num;
    g_sequence_num++; 
    /* Seteo el TTL en 64 y el resto de los campos del cabezal de LSU */
    lsu_hdr->ttl=64;
    /* Seteo el número de anuncios con la cantidad de rutas a enviar. Uso función count_routes */
    lsu_hdr->num_adv=routes_count;

    /* Creo cada LSA iterando en las enttadas de la tabla */
    struct sr_rt* rt_entry=lsu_param->sr->routing_table;
    ospfv2_lsa_t* lsa=(ospfv2_lsa_t*)(packet_lsu+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(ospfv2_hdr_t)+ sizeof(ospfv2_lsu_hdr_t)); /*apunto al principio de los anuncios*/
    while (rt_entry !=NULL){
        /* Solo envío entradas directamente conectadas y agreagadas a mano*/
        if (rt_entry->admin_dst == 1 || rt_entry->admin_dst == 0){
            /* Creo LSA con subnet, mask y routerID (id del vecino de la interfaz)*/
            lsa->mask=rt_entry->mask.s_addr;
            lsa->rid=sr_get_interface(lsu_param->sr, rt_entry->interface)->neighbor_id; 
            lsa->subnet=rt_entry->dest.s_addr; /*rt_entry->mask.s_addr;*/
            lsa=(ospfv2_lsa_t*)((uint8_t *)lsa+sizeof(ospfv2_lsa_t)); /*muevo el puntero al siguiente anuncio*/
        }
        rt_entry=rt_entry->next;
    }
    /* Calculo el checksum del paquete LSU */
    p_hdr->csum=0;
    p_hdr->csum=ospfv2_cksum(p_hdr, sizeof(ospfv2_hdr_t)+sizeof(ospfv2_lsu_hdr_t)+routes_count*sizeof(ospfv2_lsa_t));


    /* Me falta la MAC para poder enviar el paquete, la busco en la cache ARP*/
    struct sr_arpentry* entry=sr_arpcache_lookup(&lsu_param->sr->cache,lsu_param->interface->neighbor_ip);

    if (entry != NULL){ /* Envío el paquete si obtuve la MAC o lo guardo en la cola para cuando tenga la MAC*/
        printf("La MAC esta en cache send_lsu\n");
        memcpy(e_hdr->ether_dhost, entry->mac, ETHER_ADDR_LEN);
        sr_send_packet(lsu_param->sr,packet_lsu,lsu_lenght,lsu_param->interface->name);
        print_hdrs(packet_lsu,lsu_lenght);
        free(entry);
    } else {   
        printf("La MAC NO esta en cache send_lsu\n");
        struct sr_arpreq* req=sr_arpcache_queuereq(&lsu_param->sr->cache, lsu_param->interface->neighbor_ip, packet_lsu, lsu_lenght, lsu_param->interface->name);

        handle_arpreq(lsu_param->sr, req);

    }
    free(packet_lsu);
   
   /* Libero memoria */
   /*ver si hay que liberar algo mas*/

    return NULL;
} /* -- send_lsu -- */


/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_hello_packet
 *
 * Gestiona los paquetes HELLO recibidos
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_hello_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, struct sr_if* rx_if)
{
    /* Obtengo información del paquete recibido */
    /* Imprimo info del paquete recibido*/
    sr_ip_hdr_t *iphdr=( sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    ospfv2_hdr_t* rx_ospfv2_hdr = (ospfv2_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    ospfv2_hello_hdr_t* rx_ospfv2_hello_hdr =(ospfv2_hello_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)+ sizeof(ospfv2_hdr_t)); 
    Debug("-> PWOSPF: Detecting PWOSPF HELLO Packet from:\n");
    Debug("      [Neighbor ID = %s]\n", inet_ntoa((struct in_addr ){.s_addr=rx_ospfv2_hdr->rid})); /* cabecera pwospf */
    Debug("      [Neighbor IP = %s]\n", inet_ntoa((struct in_addr ){.s_addr=iphdr->ip_src})); /* cabecera ip */
    Debug("      [Network Mask = %s]\n", inet_ntoa((struct in_addr ){.s_addr=rx_ospfv2_hello_hdr->nmask}));   /* cabecera hello */
    

    /* Chequeo checksum */

    if (rx_ospfv2_hdr->csum != ospfv2_cksum(rx_ospfv2_hdr, sizeof(ospfv2_hdr_t)+sizeof(ospfv2_hello_hdr_t))) {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid checksum\n");
        return;
    }
    /* Chequeo de la máscara de red */
    if (rx_ospfv2_hello_hdr->nmask != rx_if->mask) {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello network mask\n");
        return;
    }

    /* Chequeo del intervalo de HELLO */
    if (ntohs(rx_ospfv2_hello_hdr->helloint) != OSPF_DEFAULT_HELLOINT) {
        Debug("-> PWOSPF: HELLO Packet dropped, invalid hello interval\n");
        return;
    }

    /* Seteo el vecino en la interfaz por donde llegó y actualizo la lista de vecinos */
    rx_if->neighbor_id=rx_ospfv2_hdr->rid; 
    rx_if->neighbor_ip=iphdr->ip_src;
    struct ospfv2_neighbor* neighbor=g_neighbors;

    while (neighbor != NULL && neighbor->neighbor_id.s_addr != rx_if->neighbor_id) {
        neighbor = neighbor->next;
    }
    /* Si es un nuevo vecino, debo enviar LSUs por todas mis interfaces/
    / Recorro todas las interfaces para enviar el paquete LSU /
    / Si la interfaz tiene un vecino, envío un LSU */
    if (neighbor == NULL) { 
        printf("nuevo vecino\n");                                                        
        add_neighbor(g_neighbors, create_ospfv2_neighbor((struct in_addr){.s_addr = rx_if->neighbor_id}));/* revisar */
        pwospf_lock(sr->ospf_subsys);/*Region critica*/
        struct sr_if* iface=sr->if_list;
        powspf_hello_lsu_param_t* lsu_param=malloc(sizeof(powspf_hello_lsu_param_t));     
        lsu_param->sr=sr;
        while (iface != NULL) {
            lsu_param->interface=iface;
            
            if(iface->neighbor_id!=0){
                send_lsu(lsu_param);
            }
            iface=iface->next;
        }
        pwospf_unlock(sr->ospf_subsys); /*fin region critica*/
        free(lsu_param);
    } else {
        neighbor->alive=OSPF_NEIGHBOR_TIMEOUT;
    } 
        
} /* -- sr_handle_pwospf_hello_packet -- */


/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_lsu_packet
 *
 * Gestiona los paquetes LSU recibidos y actualiza la tabla de topología
 * y ejecuta el algoritmo de Dijkstra
 *
 *---------------------------------------------------------------------*/

void* sr_handle_pwospf_lsu_packet(void* arg)
{
    powspf_rx_lsu_param_t* rx_lsu_param = ((powspf_rx_lsu_param_t*)(arg));
    /*prueba*/

    /* Obtengo el vecino que me envió el LSU*/
    /* Imprimo info del paquete recibido*/
    struct in_addr next_hop_id;
    next_hop_id.s_addr=rx_lsu_param->rx_if->neighbor_id;
    struct in_addr next_hop_ip;
    next_hop_ip.s_addr=rx_lsu_param->rx_if->neighbor_ip;

    Debug("-> PWOSPF: Detecting LSU Packet from [Neighbor ID = %s, IP = %s]\n", inet_ntoa(next_hop_id), inet_ntoa(next_hop_ip));
    
    ospfv2_hdr_t *hdr_ospf=(ospfv2_hdr_t *)(rx_lsu_param->packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
    /* Chequeo checksum */
    if(hdr_ospf->csum!=ospfv2_cksum(hdr_ospf,rx_lsu_param->length-(sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)))){
        Debug("-> PWOSPF: LSU Packet dropped, invalid checksum\n");
        return NULL;
    }
    /* Obtengo el Router ID del router originario del LSU y chequeo si no es mío*/
    if(hdr_ospf->rid==g_router_id.s_addr){

        Debug("-> PWOSPF: LSU Packet dropped, originated by this router\n");
        return NULL;
    }
    ospfv2_lsu_hdr_t *hdr_lsu =(ospfv2_lsu_hdr_t *)(rx_lsu_param->packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(ospfv2_hdr_t));
    struct in_addr source_rid;
    source_rid.s_addr=hdr_ospf->rid;
    /* Obtengo el número de secuencia y uso check_sequence_number para ver si ya lo recibí desde ese vecino*/
    if(!check_sequence_number(g_topology,source_rid,hdr_lsu->seq)){
        Debug("-> PWOSPF: LSU Packet dropped, repeated sequence number\n");
        return NULL;
    }
    /* Itero en los LSA que forman parte del LSU. Para cada uno, actualizo la topología.*/
    Debug("-> PWOSPF: Processing LSAs and updating topology table\n");    
    uint32_t number_advertisements =hdr_lsu->num_adv;
    ospfv2_lsa_t *link=(ospfv2_lsa_t *)(rx_lsu_param->packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(ospfv2_hdr_t)+sizeof(ospfv2_lsu_hdr_t));/*Primer link lsu*/
    struct in_addr subnet;
    struct in_addr mask;
    struct in_addr rid;
    
    while(number_advertisements!=0){
        /* Obtengo subnet */
        /* Obtengo vecino */
        /*Obtengo mask*/
        subnet.s_addr=link->subnet;
        mask.s_addr=link->mask;
        rid.s_addr=link->rid;        
        /* Imprimo info de la entrada de la topología */
        Debug("      [Subnet = %s]", inet_ntoa(subnet));
        Debug("      [Mask = %s]", inet_ntoa(mask));
        Debug("      [Neighbor ID = %s]\n", inet_ntoa(rid));
        /* LLamo a refresh_topology_entry*/
        /*struct pwospf_topology_entry* first_entry, struct in_addr router_id, struct in_addr net_num, struct in_addr net_mask, 
        struct in_addr neighbor_id, struct in_addr next_hop, uint16_t sequence_num*/

        refresh_topology_entry(g_topology,(struct in_addr){.s_addr=hdr_ospf->rid},subnet,mask,rid,next_hop_ip,hdr_lsu->seq);

        link=(ospfv2_lsa_t *)((uint8_t *)link+sizeof(ospfv2_lsa_t));
        number_advertisements--;
    }
               
    /* Imprimo la topología */
    Debug("\n-> PWOSPF: Printing the topology table\n");
    print_topolgy_table(g_topology);

    /* Ejecuto Dijkstra en un nuevo hilo (run_dijkstra)*/
    dijkstra_param_t dij_param;
    dij_param.sr=rx_lsu_param->sr;
    dij_param.mutex=g_dijkstra_mutex;
    dij_param.rid=g_router_id;
    dij_param.topology=g_topology;
    pthread_create(&g_dijkstra_thread, NULL, run_dijkstra, &dij_param);

    
    /* Flooding del LSU por todas las interfaces menos por donde me llegó */
    struct sr_if *aux=rx_lsu_param->sr->if_list;

    sr_ethernet_hdr_t  *hdr_eth=(sr_ethernet_hdr_t*)(rx_lsu_param->packet);

    sr_ip_hdr_t * hdr_ip=(sr_ip_hdr_t*)(rx_lsu_param->packet+sizeof(sr_ethernet_hdr_t));

    hdr_lsu->ttl--;

    if(hdr_lsu->ttl<=0){/*Ajusto aca el ttl de ospf*/
        return NULL;
    }

    while(aux!=NULL){
        
        if(aux->ip!=rx_lsu_param->rx_if->ip && aux->neighbor_ip!=0 && aux->neighbor_id!=0){
            /* Seteo MAC de origen */
            memcpy(hdr_eth->ether_shost, aux->addr, ETHER_ADDR_LEN);
            /* Ajusto paquete IP, origen y checksum*/
            hdr_ip->ip_src=aux->ip;
            hdr_ip->ip_dst=aux->neighbor_ip;
            hdr_ip->ip_sum=0;
            hdr_ip->ip_ttl=64;
            hdr_ip->ip_sum=ip_cksum(hdr_ip,sizeof(sr_ip_hdr_t));
            /* Ajusto cabezal OSPF: checksum y TTL*/
            hdr_ospf->csum=0;
            /*hdr_ospf->rid=g_router_id.s_addr;*/
            hdr_ospf->csum=ospfv2_cksum(hdr_ospf,sizeof(ospfv2_hdr_t)+sizeof(ospfv2_lsu_hdr_t)+((hdr_lsu->num_adv)*sizeof(ospfv2_lsa_t)));
            /* Envío el paquete*/

            struct sr_arpentry* entry=sr_arpcache_lookup(&rx_lsu_param->sr->cache,aux->neighbor_ip);
            /*struct sr_if* iface=sr_get_interface_given_ip(rx_lsu_param->sr,aux->ip);Interfaz de salida*/
            if (entry != NULL){ /* Envío el paquete si obtuve la MAC o lo guardo en la cola para cuando tenga la MAC*/
                printf("La MAC esta en cache sr_handle_pwospf_lsu_packet\n");
                memcpy(hdr_eth->ether_dhost, entry->mac, ETHER_ADDR_LEN);
                sr_send_packet(rx_lsu_param->sr,rx_lsu_param->packet,rx_lsu_param->length,aux->name);
                print_hdrs(rx_lsu_param->packet,rx_lsu_param->length);
                free(entry);
            } else {   
                printf("La MAC NO esta en cache sr_handle_pwospf_lsu_packet\n");
                struct sr_arpreq* req=sr_arpcache_queuereq(&rx_lsu_param->sr->cache, aux->neighbor_ip, rx_lsu_param->packet, rx_lsu_param->length, aux->name);
                handle_arpreq(rx_lsu_param->sr, req);


            }
        }
        aux=aux->next;
    }
    return NULL;
    
} /* -- sr_handle_pwospf_lsu_packet -- */


/**********************************************************************************
 * SU CÓDIGO DEBERÍA TERMINAR AQUÍ
 * *********************************************************************************/

/*---------------------------------------------------------------------
 * Method: sr_handle_pwospf_packet
 *
 * Gestiona los paquetes PWOSPF
 *
 *---------------------------------------------------------------------*/

void sr_handle_pwospf_packet(struct sr_instance* sr, uint8_t* packet, unsigned int length, struct sr_if* rx_if)
{
    /*Si aún no terminó la inicialización, se descarta el paquete recibido*/
    if (g_router_id.s_addr == 0) {
       return;
    }

    ospfv2_hdr_t* rx_ospfv2_hdr = ((ospfv2_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
    powspf_rx_lsu_param_t* rx_lsu_param = ((powspf_rx_lsu_param_t*)(malloc(sizeof(powspf_rx_lsu_param_t))));

    Debug("-> PWOSPF: Detecting PWOSPF Packet\n");
    Debug("      [Type = %d]\n", rx_ospfv2_hdr->type);

    switch(rx_ospfv2_hdr->type)
    {
        case OSPF_TYPE_HELLO:
            sr_handle_pwospf_hello_packet(sr, packet, length, rx_if);
            break;
        case OSPF_TYPE_LSU:
            rx_lsu_param->sr = sr;
            unsigned int i;
            for (i = 0; i < length; i++)
            {
                rx_lsu_param->packet[i] = packet[i];
            }
            rx_lsu_param->length = length;
            rx_lsu_param->rx_if = rx_if;
            pthread_attr_t attr;
            pthread_attr_init(&attr);
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            pthread_t pid;
            pthread_create(&pid, &attr, sr_handle_pwospf_lsu_packet, rx_lsu_param);
            break;
    }
} /* -- sr_handle_pwospf_packet -- */

