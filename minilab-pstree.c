// 获取命令行参数，根据要求设置标志变量的数值
// 获取系统中所有进程的编号(每个进程都会有唯一编号)并保存至列表中
// 对列表中的每个编号，获取其父进程
// 在内存中将树创建好，并按照命令行参数要求排序
// 输出树到终端上
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>

typedef struct Node
{
    pid_t pid;
    pid_t ppid;
    struct Node **children;
    int num_children;
    char comm[100];
} Node;

Node **nodes;

bool showPid = false;
bool numericSort = false;
bool version = false;

size_t num_pids = 0;
#define MAX_PATH_LENGTH 1000

// 获取命令行参数，根据要求设置标志变量的数值
void getParamters(int argc, char *argv[])
{
    for (int i = 1; i < argc; i++)
    {
        if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--show-pids") == 0)
        {
            showPid = true;
        }
        else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--numeric-sort") == 0)
        {
            numericSort = true;
        }
        else if (strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0)
        {
            version = true;
            break;
        }
        else
        {
            assert(false);
        }
    }
    assert(!argv[argc]); // 注意argv最后是否位空指针
}

// 获取系统中所有进程的编号(每个进程都会有唯一编号)并保存至列表中
pid_t *getPids()
{
    DIR *proc_dir = opendir("/proc");
    if (proc_dir == NULL)
    {
        perror("opendir failed");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    int num_entries = 0;
    while ((entry = readdir(proc_dir)) != NULL)
    {
        // Check if the directory entry is a directory and its name consists only of digits
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0]))
        {
            num_entries++;
        }
    }

    rewinddir(proc_dir);

    // allocate space for the list
    pid_t *pid_list = malloc(num_entries * sizeof(pid_t));
    if (pid_list == NULL)
    {
        perror("malloc failed");
        exit(EXIT_FAILURE);
    }

    // add pids to the list
    int i = 0;
    while ((entry = readdir(proc_dir)) != NULL)
    {
        if (entry->d_type == DT_DIR && isdigit(entry->d_name[0]))
        {
            pid_list[i++] = atoi(entry->d_name);
        }
    }

    closedir(proc_dir);

    return pid_list;
}

// 对列表中的每个编号，获取其父进程
// for example /proc/1412/ vim stat then we can see in it the 4th string is its parent ppid which is 1392
int *getParent(pid_t *pid_list)
{

    while (pid_list[num_pids] != 0)
    {
        num_pids++;
    }

    char path[MAX_PATH_LENGTH];
    char stat_str[256];                           // 存储从文件中读取的字符串的缓冲区
    char *token;                                  // 用于分割字符串的指针
    int *values = malloc(num_pids * sizeof(int)); // 存储第四个值的整数数组

    for (int i = 0; i < num_pids; i++)
    {
        sprintf(path, "/proc/%d/stat", pid_list[i]);

        FILE *fp = fopen(path, "r");
        if (fp == NULL)
        {
            perror("fopen failed");
            exit(EXIT_FAILURE);
        }

        fgets(stat_str, sizeof(stat_str), fp);

        fclose(fp);

        // 分割字符串并获取第四个值
        token = strtok(stat_str, " ");
        for (int j = 1; j < 4; j++)
        {
            token = strtok(NULL, " ");
        }
        values[i] = atoi(token);
    }
    return values;
}

// 建树并打印
/*
为流程树中的每个节点定义一个数据结构，其中包含 PID、父 PID 和任何子 PID。
创建一个空哈希表来存储树的节点，使用 PID 作为键。
遍历 pid_t 数组，为每个 PID 创建一个节点，将父 PID 设置为 int 数组中的相应值。
对于每个创建的节点，将其添加到哈希表中。
再次遍历哈希表并将每个节点添加到其父节点的子节点列表中。
找到根节点（具有不在哈希表中的父 PID 的节点）并将其作为进程树的根返回。
*/

void create_node(Node *node, pid_t pid, pid_t ppid)
{
    node->pid = pid;
    node->ppid = ppid;
    node->children = NULL;
    node->num_children = 0;

    sprintf(node->comm, "/proc/%d/comm", pid);

    FILE *fp = fopen(node->comm, "r");
    if (fp == NULL)
    {
        perror("fopen failed");
        exit(1);
    }

    fgets(node->comm, sizeof(node->comm), fp);
    fclose(fp);
}

void add_child(Node *parent, Node *child)
{
    parent->children = (Node **)realloc(parent->children, (parent->num_children + 1) * sizeof(Node *));
    parent->children[parent->num_children++] = child;
}

Node *get_process_tree(pid_t *pid_array, int *parent_array)
{
    size_t length = (size_t)num_pids;
    Node *root = NULL;
    size_t i;
    nodes = (Node **)malloc(length * sizeof(Node *));

    // Step 1: Create nodes for each PID
    for (i = 0; i < length; i++)
    {
        nodes[i] = (Node *)malloc(sizeof(Node));
        create_node(nodes[i], pid_array[i], parent_array[i]);
    }

    // Step 2: Create hash table of nodes
    Node **node_hash = (Node **)calloc(length, sizeof(Node *));
    for (i = 0; i < length; i++)
    {
        node_hash[pid_array[i]] = nodes[i];
    }

    // Step 3: Add each node to its parent's list of children
    for (i = 0; i < length; i++)
    {
        if (nodes[i]->ppid != 0)
        {
            Node *parent = node_hash[nodes[i]->ppid];
            add_child(parent, nodes[i]);
        }
    }

    // Step 4: Find the root node
    for (i = 0; i < length; i++)
    {
        if (node_hash[pid_array[i]]->ppid == 0)
        {
            root = node_hash[pid_array[i]];
            break;
        }
    }

    free(node_hash);

    return root;
}

int compare_pids(const void *a, const void *b)
{
    const Node *node_a = *(const Node **)a;
    const Node *node_b = *(const Node **)b;

    return node_a->pid - node_b->pid;
}

void printNodeWithPid(Node *node, int depth)
{

    printf("%*s|- %s(%d)\n", depth * 2, "", node->comm, node->pid);

    // Recursively print each child node with increased depth
    for (int i = 0; i < node->num_children; i++)
    {
        printNodeWithPid(node->children[i], depth + 1);
    }
}

void printNodeWithPid_numeric(Node *node, int depth)
{

    printf("%*s|- %s(%d)\n", depth * 2, "", node->comm, node->pid);

    // Sort the child nodes by their PIDs in ascending order
    qsort(node->children, node->num_children, sizeof(Node *), compare_pids);

    // Recursively print each child node with increased depth
    for (int i = 0; i < node->num_children; i++)
    {
        printNodeWithPid_numeric(node->children[i], depth + 1);
    }
}

void printNodeWithoutPid(Node *node, int depth)
{

    printf("%*s|- %s\n", depth * 2, "", node->comm);

    // Recursively print each child node with increased depth
    for (int i = 0; i < node->num_children; i++)
    {
        printNodeWithoutPid(node->children[i], depth + 1);
    }
}

void printNodeWithoutPid_numeric(Node *node, int depth)
{

    printf("%*s|- %s\n", depth * 2, "", node->comm);

    // Sort the child nodes by their PIDs in ascending order
    qsort(node->children, node->num_children, sizeof(Node *), compare_pids);

    // Recursively print each child node with increased depth
    for (int i = 0; i < node->num_children; i++)
    {
        printNodeWithoutPid_numeric(node->children[i], depth + 1);
    }
}

void printProcessTree(Node *root)
{
    if (version == true)
    {
        printf("2023/4 By rose_is_blue\n");
        printf("note that rose_is_blue is the nickname of Kaa\n");
        printf("thank you for your support");
    }
    else
    {
        if (showPid == true && numericSort == true)
        {
            printNodeWithPid_numeric(root, 0);
        }
        else if (showPid == true && numericSort == false)
        {
            printNodeWithPid(root, 0);
        }
        else if (showPid == false && numericSort == true)
        {
            printNodeWithoutPid_numeric(root, 0);
        }
        else if (showPid == false && numericSort == false)
        {
            printNodeWithoutPid(root, 0);
        }
    }
}

int main(int argc, char *argv[])
{

    getParamters(argc, argv);

    pid_t *pid_list = getPids();
    int *parent_list = getParent(pid_list);

    Node *root = get_process_tree(pid_list, parent_list);

    printProcessTree(root);
    return 0;
}