#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <zlib.h>

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
} __attribute__((packed)) input_msg_t;

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


int extract_pairs(FILE *fd, pair_t *pairs, size_t *pairs_num);
int process_pairs(pair_t *pairs, size_t pairs_num, output_msg_t *out, size_t *output_msg_num);
int save_outputs(FILE *fd_out, output_msg_t *out_msgs, size_t out_msgs_num);

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

    /* CRC32 calculating
    
        const char* data = "Hello, world!";
        uLong crc = crc32_z(0xFFFFFFFF, (const Bytef*)data, strlen(data));
        crc = crc ^ 0xFFFFFFFF;  // XOR the final CRC with 0xFFFFFFFF
        printf("CRC32 checksum: 0x%lx\n", crc);
    */

    memset(&pair.input_msg.payload, 0, sizeof(pair.input_msg.payload));
    memset(&pair.input_msg.data, 0, sizeof(pair.input_msg.data));

    FILE *fd_out = fopen(OUTPUT_FILE_NAME, "a");
    if (fd_out == NULL) {
        printf("Error opening %s file\n", OUTPUT_FILE_NAME);
        return 1;
    }

    FILE *fd_in = fopen(INPUT_FILE_NAME, "r");
    if (fd_in == NULL) {
        fprintf(fd_out, "Error opening %s file\n", INPUT_FILE_NAME);
        return 1;
    }

    pair_t *pairs = NULL;
    size_t pairs_num = 0;

    ret = extract_pairs(fd_in, pairs, &pairs_num);
    if(ret != 0){
        fprintf(fd_out, "Pairs extracting error\n");
        return 1;
    }
    
    output_msg_t *output = NULL;
    size_t output_num = 0;

    ret = process_pairs(pairs, pairs_num, output, &output_num);
    if(ret != 0){
        fprintf(fd_out, "Pairs processing error\n");
        return 1;
    }

    ret = save_outputs(fd_out, output, output_num);
    if(ret != 0){
        fprintf(fd_out, "Saving outputs error\n");
        return 1;
    }

    fclose(fd_in);
    fclose(fd_out);

    return 0;
}

//
int extract_pairs(FILE *fd, pair_t *pairs, size_t *pairs_num){

    bool in_message = false;
    const size_t bufsize = 2048;

    uint8_t *buffer = (uint8_t *) malloc(bufsize);

    if(fd == NULL || buffer == NULL){
        return 1;
    }

    memset(buffer, 0, bufsize);

    ssize_t read_bytes = 0;

    // Here it's supposed buffer has enough size
    while ((read_bytes = fread(buffer, 1, sizeof(pair_t) + strlen(MSG_PREFIX) + strlen(MASK_PREFIX), fd)) != 0)
    {
        if (read_bytes == -1) {
            printf("%s\n", strerror(errno));
            return 1;
        }

        uint8_t *msg_ptr = NULL;
        uint8_t *mask_ptr = NULL;

        for(int i = 0; i < read_bytes; i++){
            if(buffer[i] == MSG_PREFIX[0]){
                if(memcmp(&buffer[i], MSG_PREFIX, strlen(MSG_PREFIX)) == 0){
                    msg_ptr = &buffer[i] + strlen(MSG_PREFIX);
                }
            }
            if(buffer[i] == MASK_PREFIX[0]){
                if(memcmp(&buffer[i], MASK_PREFIX, strlen(MASK_PREFIX)) == 0){
                    mask_ptr = &buffer[i] + strlen(MASK_PREFIX);
                }
            }
        }

        if(*pairs_num == 0){
            pairs = (pair_t *) malloc(sizeof(pair_t));
            if(pairs == NULL){
                return 1;
           }
        } else{
            pairs = realloc(pairs, *pairs_num * sizeof(pair_t));
            if(pairs == NULL){
                return 1;
            }
        }

        pair_t *curr_pair = pairs + *pairs_num * sizeof(pair_t);
        curr_pair->mask = 0; 
        memcpy(&curr_pair->input_msg, msg_ptr, sizeof(input_msg_t));
        curr_pair->mask = *(uint32_t *)mask_ptr;
        (*pairs_num)++;
    }

    return 0;
}

void DumpHex(const void* data, size_t size) {
    
    uint16_t curr_len;
    int n;
    char buff[2048];

    memset(buff, 0, sizeof(buff));
    
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
    n = snprintf(buff, sizeof(buff), "\n");
    if (n<0){
        printf("snprnt_ERR_1\n");
        return;
    }
	for (i = 0; i < size; ++i) {
        curr_len = strlen(buff);
		n = snprintf(buff + curr_len, sizeof(buff) - curr_len, "%02X ", ((unsigned char*)data)[i]);
        if (n<0){
            printf("snprnt_ERR_2\n");
            return;
        }
        if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
            curr_len = strlen(buff);
            n = snprintf(buff + curr_len, sizeof(buff) - curr_len, " ");
            if (n<0){
                printf("snprnt_ERR_3\n");
                return;
            }
			if ((i+1) % 16 == 0) {
                curr_len = strlen(buff);
                n = snprintf(buff + curr_len, sizeof(buff) - curr_len, "|  %s \n", ascii);
                if (n<0){
                    printf("snprnt_ERR_4\n");
                    return;
                }
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
                    curr_len = strlen(buff);
                    n = snprintf(buff + curr_len, sizeof(buff) - curr_len, " ");
                    if (n<0){
                        printf("snprnt_ERR_5\n");
                        return;
                    }
				}
				for (j = (i+1) % 16; j < 16; ++j) {
                    curr_len = strlen(buff);
                    n = snprintf(buff + curr_len, sizeof(buff) - curr_len, "   ");
                    if (n<0){
                        printf("snprnt_ERR_6\n");
                        return;
                    }
				}
                curr_len = strlen(buff);
                n = snprintf(buff + curr_len, sizeof(buff) - curr_len, "|  %s \n", ascii);
                if (n<0){
                    printf("snprnt_ERR_7\n");
                    return;
                }
			}
		}
	}
    curr_len = strlen(buff);
    n = snprintf(buff + curr_len, sizeof(buff) - curr_len, "\n");
    if (n<0){
        printf("snprnt_ERR_8\n");
        return;
    }
    buff[sizeof(buff) - 1] = 0;
    printf("%s", buff);
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

// Process pairs
int process_pairs(pair_t *pairs, size_t pairs_num, output_msg_t *out, size_t *output_msg_num){
    
    if(pairs == NULL) {
        return 1;
    }

    for(int i = 0; i < pairs_num; i++){

    }

    // TOOD: Free allocated memory

    return 0;
}

//
int save_outputs(FILE *fd_out, output_msg_t *out_msgs, size_t out_msgs_num){
    return 0;
}