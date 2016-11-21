/* Hexdump utility. */

#include <zephyr.h>
#include <misc/printk.h>
#include <string.h>

/*
 * Perform a hexdump of the given data.  The working buffer is static,
 * so this shouldn't be reentered.
 */
void pdump(const void *data, unsigned len)
{
	char ascii[19];
	char hex[51];
	char *pascii = ascii;
	char *phex = hex;
	const unsigned char *cdata;
	unsigned pos = 0;
	unsigned tmp;
	unsigned byte;

	cdata = data;
	while (len > 0) {
		byte = *cdata;
		tmp = byte >> 4;
		tmp += tmp > 9 ? 87 : 48;
		*(phex++) = tmp;
		tmp = byte & 0x0F;
		tmp += tmp > 9 ? 87 : 48;
		*(phex++) = tmp;
		*(phex++) = ' ';

		if (byte >= 32 && byte <= 126)
			*(pascii++) = byte;
		else
			*(pascii++) = '.';

		if ((pos & 15) == 7) {
			*(phex++) = '-';
			*(phex++) = ' ';
		}

		if ((pos & 15) == 15 || len == 1) {
			*phex = '\0';
			*pascii = '\0';
			printk("%x  %s |%s|\n", (pos & ~15), hex, ascii);

			phex = hex;
			pascii = ascii;
		}

		pos++;
		len--;
		cdata++;
	}
}
