#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/* Structure of disjoint prefix binary trie node */
struct BtNode{
    BtNode  *left;      /* for 0 */
    BtNode  *right;     /* for 1 */
    int     verdict;
};

/* Initialize disjoint prefix binary trie node */
BtNode* init_btnode(){
    BtNode *ret = (BtNode *)malloc(sizeof(BtNode));
    ret->left = NULL;
    ret->right = NULL;
    ret->verdict = -1;
    return ret;
}

/* Clean up disjoint prefix binary trie */
void free_bt(BtNode *root){

    if(root->left != NULL){
        free_bt(root->left);
    }
    if(root->right != NULL){
        free_bt(root->right);
    }

    free(root);
}

/* Insert a rule */
void insert_rule(BtNode *root, uint32_t prefix, int prelen, int portnum){
    static int     n_rules = 0;

    n_rules ++;

    if( prelen == 0 ){
        root->verdict = portnum;
        return;
    }

    uint32_t    temp_prefix = prefix;
    BtNode      *curr_node = root;
    for(int i=0 ; i < prelen ; i++){
        int     curr_bit = (temp_prefix & 0x80000000) ? 1 : 0;
        if(curr_bit == 0){
            if(curr_node->left == NULL){
                curr_node->left = init_btnode();
            }
            curr_node = curr_node->left;
        }
        else{
            if(curr_node->right == NULL){
                curr_node->right = init_btnode();
            }
            curr_node = curr_node->right;
        }
        temp_prefix = temp_prefix << 1;
    }

    if( curr_node->verdict != -1 ){
        fprintf(stderr, "Error: Rule #%d - overwriting a previous rule!! \n", n_rules);
    }
    curr_node->verdict = portnum;
}

/* binary trie leaf pushing */
void leaf_pushing(BtNode *root){
	BtNode      *curr_node = root;
	BtNode		*left_child, *right_child;
	int 		curr_verdict = -1;
    /* if current node is a internal node with routing rule */
	if( curr_node->verdict != -1 && (curr_node->left != NULL || curr_node->right != NULL )){
		curr_verdict = curr_node->verdict;
        curr_node->verdict = -1;
        /* add left inherit leaf */
        if(curr_node->left == NULL){
            curr_node->left = init_btnode();
            left_child = curr_node->left;
            left_child->verdict = curr_verdict;
        }
        /* left child inherits current node's verdict */
        else{
            left_child = curr_node->left;
            if( left_child->verdict == -1 )
                left_child->verdict = curr_verdict;
            /* continue pushing left child, until a leaf */
            leaf_pushing(left_child);
        }
        /* add right inherit leaf */
        if(curr_node->right == NULL){
            curr_node->right = init_btnode();
            right_child = curr_node->right;
            right_child->verdict = curr_verdict;
        }
        /* right child inherits current node's verdict */
        else{
            right_child = curr_node->right;
            if( right_child->verdict == -1 )
                right_child->verdict = curr_verdict;
            /* continue pushing right child, until a leaf */
            leaf_pushing(right_child);
	   }
    }
    /* if current node is NOT a internal node with routing rule */
    else{
        if(curr_node->left != NULL){
            left_child = curr_node->left;
			leaf_pushing(left_child);
		}
		if(curr_node->right != NULL){
			right_child = curr_node->right;
			leaf_pushing(right_child);
		}
	}
}
	
/* Look up an IP address (represented in a uint32_t) */
int lookup_ip(BtNode *root, uint32_t ip){
    uint32_t    temp_ip = ip;
    BtNode      *curr_node = root;
    int         curr_bit = 0;

    while(1){
        curr_bit = (temp_ip & 0x80000000) ? 1 : 0;
        if(curr_bit == 0){
            if(curr_node->left == NULL)     return curr_node->verdict;
            else                            curr_node = curr_node->left;
        }
        else{
            if(curr_node->right == NULL)    return curr_node->verdict;
            else                            curr_node = curr_node->right;
        }
        temp_ip = temp_ip << 1;
    }
}
