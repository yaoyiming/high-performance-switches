#include <arpa/inet.h>
#include <stdio.h>
#include <vector>
#include <stdlib.h>
#include <math.h>

typedef struct{
     uint32_t     prefix;
     int          prelen, portnum, biggerthan, equalto;
} point;

/* Used in the sorting function */
bool operator<(const point &a, const point &b){
    if(a.prefix != b.prefix)
        return a.prefix < b.prefix;
    else
        return a.prelen < b.prelen;
}

using namespace std;
vector<point> endpoints;    /* List all the endpoints */
int num_point = 0;              /* Count all the endpoints */

/* Fill the content from the routing table to a binary tree point */
void fillin_point(point &temp, uint32_t prefix, int prelen, int portnum){
     temp.prefix = prefix;
     temp.prelen = prelen;
     temp.portnum = portnum;
}

/* Longest prefix match, return the port number of the longest matching prefix */
int compare_point(int i){
     int port;
     if(endpoints[i].prefix == endpoints[i + 1].prefix)
          port = compare_point(i + 1);
     else
          port = endpoints[i].portnum;
     return port;
}

/* Find the smallest prefix range that contains the current point/entry/prefix range */
int find_port(int const pointnum){
     int i = pointnum - 1;
     if (i == -1)
         printf("Error when finding bigger than port number!\n");
     for(; i > -1; i--) {
         long int range = pow(2, (32 - endpoints[i].prelen));
         /* When higher point */
         if(endpoints[i].prefix & 0x00000001)
             continue;
         /* When lower point */
         if(endpoints[pointnum].prefix >= (endpoints[i].prefix + range - 1))
             continue;
         return endpoints[i].portnum;
     }  
     return 0;    /* For the last ip address which have no bigger than port number */
}

/* Set the port number when the IP for lookup satisfy '=' */
void set_equalport(int num_point){
    int i;
    for(i = 0; i < num_point; i++) {
        if (i != num_point - 1){
            endpoints[i].equalto = compare_point(i);
        }
        else
            endpoints[i].equalto = endpoints[i].portnum;
    }
    return;
}

/* Set the port number when the IP for lookup satisfy '>' */
void set_biggerport(int const num_point){
    int i;
    for(i = 0; i < num_point; i++) {
        /* When the prefix length equals to 32, use the previous biggerthan */
        if(endpoints[i].prelen == 32)
            endpoints[i].biggerthan = endpoints[i - 1].biggerthan;
        /* When higher point, i.e. ends with '1' */
        else if(endpoints[i].prefix & 0x00000001)
            endpoints[i].biggerthan = find_port(i);
        /* When lower point */
        else
            endpoints[i].biggerthan = endpoints[i].equalto;
    }
    return;
}

/* Look up an IP address through binary tree */
int lookup_ip(uint32_t ip){
    uint32_t    temp_ip = ip;
    int         first, last;
    int         portnum = 0;
    int         middle;
    first = 0;
    last = num_point - 1;
    while (first <= last) {
        middle = (first + last)/2;
        if(temp_ip == endpoints[middle].prefix) {
            portnum = endpoints[middle].portnum;
            return portnum;
        }
        else if(temp_ip > endpoints[middle].prefix) {
            /* Update the port number */
            portnum = endpoints[middle].biggerthan;
            first = middle + 1;
        }
        else if(temp_ip < endpoints[middle].prefix) {
            last = middle - 1;
        }
    }
    return portnum;
}