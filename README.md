# ddon_pcap_split
ddon_pcap_split is a small CLI tool to parse DDON pcaps and split them into JSON files per connection and server type.

**This tool does not perform any decryption on the packets.** Each output json file has it's own Camellia common key which will need to be bruteforced

## Usage
```
go get -u github.com/Andoryuuta/ddon_pcap_split
```
```
# Single file
>>> ddon_pcap_split -i [some_file.pcap]

# Bulk processing
>>> ddon_pcap_split -idir [input_folder] -odir [output_folder]
```
