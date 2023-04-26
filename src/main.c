#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define INPUT_FILE_NAME "data_in.txt"
#define OUTPUT_FILE_NAME "data_out.txt"

#define MSG_PREFIX "mess="
#define MASK_PREFIX "mask="

/*
    Message input format:
    |-------------------------------------------|
    |  0   |   1    | 2...253 | 254...257       |
    |-------------------------------------------|
    | Type | Length |        Payload            |
    |-------------------------------------------| 
    |               |   data  |    CRC-32       |
    |-------------------------------------------| 
*/
typedef struct {
    uint8_t type;         // 1 byte
    uint8_t length;       // 1 byte
    uint8_t payload[255]; // 256 bytes
    uint8_t data[252];    // 252 bytes
    uint32_t crc32;       // 4 bytes
} input_msg_t;

/*
    Output information format (for each message):
    - message type
    - initial message length
    - initial message data bytes
    - initial CRC-32
    - modified message length
    - modified message data bytes with mask
    - modified CRC-32
*/
typedef struct {
    uint8_t type;
    uint8_t init_length;
    uint8_t *init_data;
    uint32_t init_crc32;

    uint8_t mod_length;
    uint8_t *mod_data;
    uint32_t mod_crc32;
} output_msg_t;

typedef struct {
    input_msg_t input_msg;
    uint32_t    mask;
} __attribute__((packed)) pair_t;


int main(){

    int ret = 0;

    pair_t pair = {
        .input_msg = {
            .type = 1,
            .length = 255,
            .payload[0] = 0,
            .data[0] = 0,
            .crc32 = 0x12345678,
        },
        .mask = 0xDEADBEEF
    };

    memset(&pair.input_msg.payload, 0, sizeof(pair.input_msg.payload));
    memset(&pair.input_msg.data, 0, sizeof(pair.input_msg.data));

    serialize_and_write_pair("pair", &pair);

    // FILE *fd_out = fopen(OUTPUT_FILE_NAME, "a");
    // if (fd_out == NULL) {
    //     printf("Error opening %s file\n", OUTPUT_FILE_NAME);
    //     return 1;
    // }

    // FILE *fd_in = fopen(INPUT_FILE_NAME, "r");
    // if (fd_in == NULL) {
    //     fprintf(fd_out, "Error opening %s file\n", INPUT_FILE_NAME);
    //     return 1;
    // }

    // pair_t *pairs = NULL;
    // size_t pairs_num = 0;

    // ret = extract_pairs(fd_in, pairs, &pairs_num);
    // if(ret != 0){
    //     fprintf(fd_out, "Pairs extracting error\n");
    //     return 1;
    // }
    
    // output_msg_t *output = NULL;
    // size_t output_num = 0;

    // ret = process_pairs(pairs, pairs_num, output, &output_num);
    // if(ret != 0){
    //     fprintf(fd_out, "Pairs processing error\n");
    //     return 1;
    // }

    // ret = save_outputs(fd_out, output, output_num);
    // if(ret != 0){
    //     fprintf(fd_out, "Saving outputs error\n");
    //     return 1;
    // }

    return 0;
}

//
int extract_pairs(FILE *fd, pair_t *pairs, size_t *pairs_num){

    return 0;
}

//
int serialize_and_write_pair(const char *filename, pair_t *pair){

    if(filename == NULL || pair == NULL){
        return 1;
    }

    FILE *fd = fopen(filename, "w+");
    if (fd == NULL) {
        return 1;
    }

    fprintf(fd, "%s", MSG_PREFIX);

    size_t written = fwrite(&pair->input_msg, sizeof(char), sizeof(input_msg_t), fd);
    if(written != sizeof(input_msg_t)){
        fclose(fd);
        return 1;
    }

    fprintf(fd, "%s", MASK_PREFIX);

    written = fwrite(&pair->mask, sizeof(char), sizeof(pair->mask), fd);
    if(written != sizeof(pair->mask)){
        fclose(fd);
        return 1;
    }

    fclose(fd);

    return 0;
}

int make_pair(pair_t *out){
    
}

//
int process_pairs(pair_t *pairs, size_t pairs_num, output_msg_t *out, size_t *output_msg_num){
    
    if(pairs == NULL) {
        return 1;
    }

    for(int i = 0; i < pairs_num; i++){

    }

    return 0;
}

//
int save_outputs(FILE *fd_out, output_msg_t *out_msgs, size_t out_msgs_num){
    return 0;
}