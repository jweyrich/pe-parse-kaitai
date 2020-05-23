#include <fstream>
#include <iostream>
#include "microsoft_pe.h"

int main(int argc, char *argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <file>" << std::endl;
		return EXIT_FAILURE;
	}

	const std::string filepath = argv[1];

	//std::string buf;
	//std::istringstream input_stream(buf);
	std::ifstream input_stream(filepath, std::ifstream::binary);
	if (!input_stream.is_open()) {
		std::cerr << "Failed to open " << filepath << std::endl;
		return EXIT_FAILURE;
	}

	kaitai::kstream kstream { &input_stream };
	microsoft_pe_t parsed { &kstream };

	// MZ
	microsoft_pe_t::image_dos_header_t *dos_hdr = parsed.dos_header();
	if (dos_hdr == nullptr) {
		return EXIT_FAILURE;
	}
	std::cout << "DOS magic: " << std::hex << dos_hdr->magic() << std::endl;
	std::cout << "DOS lfanew: " << std::hex << dos_hdr->lfanew() << std::endl;

	// PE
	microsoft_pe_t::pe_header_t *pe_hdr = parsed.pe_header();
	if (pe_hdr == nullptr) {
		return EXIT_FAILURE;
	}
	std::cout << "PE pe_signature: " << pe_hdr->pe_signature() << std::endl;

	// COFF
	microsoft_pe_t::image_coff_header_t *coff_hdr = pe_hdr->coff_hdr();
	if (coff_hdr != nullptr) {
		std::cout << "COFF characteristics: " << coff_hdr->characteristics() << std::endl;
		std::cout << "COFF machine: " << coff_hdr->machine() << std::endl;
	}
	
	input_stream.close();

	return EXIT_SUCCESS;
}
