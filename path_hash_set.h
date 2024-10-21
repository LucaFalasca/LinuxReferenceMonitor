#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/hashtable.h>
#include <linux/rculist.h>
#include <linux/slab.h>
#include <linux/stringhash.h>

#define HASH_SET_BITS 10  // Numero di bit per la tabella hash (es. 2^10 = 1024 bucket)
#define DEFINE_HASHSET(name) DEFINE_READ_MOSTLY_HASHTABLE(name, HASH_SET_BITS)

// Definizione della struttura del nostro hash set
struct hashset_node {
    struct hlist_node node; // Node per la lista collegata
    int key;                // Chiave da memorizzare
};

// Creazione dell'hash set
DEFINE_HASHSET(my_hashset);

// Funzione per aggiungere un elemento
void hashset_add(char *path) {
    struct hashset_node *new_node;
    int key;
    key = hashlen_hash(hashlen_string(NULL, path)); // Calcola l'hash della stringa

    // Alloca memoria per il nuovo nodo
    new_node = kmalloc(sizeof(struct hashset_node), GFP_KERNEL);
    if (!new_node) {
        printk(KERN_ERR "Errore nell'allocazione della memoria\n");
        return;
    }
    
    new_node->key = key; // Imposta la chiave
    hash_add_rcu(my_hashset, &new_node->node, key); // Aggiungi l'elemento
}

// Funzione per controllare se un elemento esiste
int hashset_contains(char *path) {
    struct hashset_node *node;
    int key;
    key = hashlen_hash(hashlen_string(NULL, path)); // Calcola l'hash della stringa

    // Itera sui bucket per trovare la chiave
    hash_for_each_possible_rcu(my_hashset, node, node, key) {
        if (node->key == key) {
            return 1; // Chiave trovata
        }
    }
    return 0; // Chiave non trovata
}


// Funzione per rimuovere un elemento
void hashset_remove(char *path) {
    struct hashset_node *node;
    int key;
    key = hashlen_hash(hashlen_string(NULL, path)); // Calcola l'hash della stringa

    hash_for_each_possible_rcu(my_hashset, node, node, key) {
        if (node->key == key) {
            hash_del_rcu(&node->node); // Rimuovi dal set
            kfree(node); // Libera la memoria
            return;
        }
    }
}

// Funzione per aggiungere un elemento
void hashset_add_int(unsigned long key) {
    struct hashset_node *new_node;

    // Alloca memoria per il nuovo nodo
    new_node = kmalloc(sizeof(struct hashset_node), GFP_KERNEL);
    if (!new_node) {
        printk(KERN_ERR "Errore nell'allocazione della memoria\n");
        return;
    }
    
    new_node->key = key; // Imposta la chiave
    hash_add_rcu(my_hashset, &new_node->node, key); // Aggiungi l'elemento
}

// Funzione per controllare se un elemento esiste
int hashset_contains_int(unsigned long key) {
    struct hashset_node *node;

    // Itera sui bucket per trovare la chiave
    hash_for_each_possible_rcu(my_hashset, node, node, key) {
        if (node->key == key) {
            return 1; // Chiave trovata
        }
    }
    return 0; // Chiave non trovata
}


// Funzione per rimuovere un elemento
void hashset_remove_int(unsigned long key) {
    struct hashset_node *node;

    hash_for_each_possible_rcu(my_hashset, node, node, key) {
        if (node->key == key) {
            kfree(node); // Libera la memoria
            return;
        }
    }
}

// Funzione per inizializzare l'hash set
void hashset_init(void) {
    hash_init(my_hashset); // Inizializza la tabella hash
}

// Funzione per liberare la memoria allocata
void hashset_cleanup(void) {
    struct hashset_node *node;
    int bkt;

    // Itera su tutti i bucket e libera la memoria
    hash_for_each_rcu(my_hashset, bkt, node, node) {
        hash_del(&node->node); // Rimuovi il nodo
        kfree(node); // Libera la memoria
    }
}

void hashet_print(void) {
    struct hashset_node *node;
    int bkt;

    // Itera su tutti i bucket e stampa la chiave
    hash_for_each_rcu(my_hashset, bkt, node, node) {
        printk(KERN_INFO "Chiave: %d\n", node->key);
    }
}
