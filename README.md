# esphome-dlms




cipher text startet bei 38 bei insgesamt 139 bytes ohne start/end flag
da aes_128 nur zu 16 bytes codieren kann wäre es möglich das er nur 96 bytes nimmer

aes möglicherweise cipher text ab 38 bis -3 ohne end flag am ende des buffers




https://github.com/aburgr/smartmeter-reader/blob/main/decode.py#L48

Cosem information
https://web.archive.org/web/20170921113529/http://dlms.com/documents/archive/Excerpt_BB10.pdf



forum
--------------------
000	start flag
001-013	hdcl header
014-021	system title
023	security byte
024-027	frame counter
028-096 cipher text
097-108	gcm tag
109-110	crc checksum
111	end flag


self
--------------------
001	start flag
002-021	hdlc header
022-029 system title
030
031-032
033	security byte
034-037	frame counter
038-126	cipher text
127-138	gcm tag?
139-140	crc checksum
141	end flag