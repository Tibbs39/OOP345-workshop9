// Name:  Kenneth Yue
// Seneca Student ID: 127932176
// Seneca email:  kyue3@myseneca.ca
// Date of completion: Nov 20, 2018
//
// I confirm that the content of this file is created by me,
// with exception of the parts provided to me by my professor


// Workshop 9 - Multi-Threading
// SecureData.cpp

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <thread>
#include <future>
#include <functional>
#include "SecureData.h"

using namespace std;

namespace w9 {

	void converter(char* t, char key, int n, const Cryptor& c) {
		for (int i = 0; i < n; i++)
			t[i] = c(t[i], key);
	}

	SecureData::SecureData(const char* file, char key, ostream* pOfs)
	{
		ofs = pOfs;

		// open text file
		fstream input(file, std::ios::in);
		if (!input)
			throw string("\n***Failed to open file ") +
			string(file) + string(" ***\n");

		// copy from file into memory
		input.seekg(0, std::ios::end);
		nbytes = (int)input.tellg() + 1;

		text = new char[nbytes];

		input.seekg(ios::beg);
		int i = 0;
		input >> noskipws;
		while (input.good())
			input >> text[i++];
		text[nbytes - 1] = '\0';
		*ofs << "\n" << nbytes - 1 << " bytes copied from file "
			<< file << " into memory (null byte added)\n";
		encoded = false;

		// encode using key
		code(key);
		*ofs << "Data encrypted in memory\n";
	}

	SecureData::~SecureData() {
		delete[] text;
	}

	void SecureData::display(std::ostream& os) const {
		if (text && !encoded)
			os << text << std::endl;
		else if (encoded)
			throw std::string("\n***Data is encoded***\n");
		else
			throw std::string("\n***No data stored***\n");
	}

	// STUDENT PORTION
	void SecureData::code(char key)
	{
		// this function to uses three threads (two child threads + main thread)
		// to encrypt/decrypt the text.

		// partition string into 3 equal parts, any remaindering bytes go to partition 3
		int part = nbytes / 3;

		// partition 3
		auto convert_p3 = std::bind(converter, text + part * 2, key, nbytes - (part * 2), Cryptor());
		std::thread p3(convert_p3);
		
		// partition 2
		auto convert_p2 = std::bind(converter, text + part, key, part , Cryptor());
		std::thread p2(convert_p2);
		
		// use main thread for partition 1
		/* this was added because it felt inefficient to have the main thread doing nothing
		   while waiting on the other two threads
		*/
		converter(text, key, part, Cryptor());

		// wait for partitions 2 and 3 to finish encoding
		p2.join();
		p3.join();

		encoded = !encoded;
	}

	void SecureData::backup(const char* file) {
		if (!text)
			throw std::string("\n***No data stored***\n");
		else if (!encoded)
			throw std::string("\n***Data is not encoded***\n");
		else
		{
			// STUDENT PORTION
			// open a binary file for writing
			std::ofstream fout(file, std::ios::binary);

			if (!fout.good()) throw std::string("\n***Could not open file***\n");

			// write data into the binary file and close the file
			fout.write(text, nbytes);
			fout.close();
		}
	}

	void SecureData::restore(const char* file, char key) {
		// STUDENT PORTION
		// open binary file for reading
		std::ifstream fin(file, std::ios::binary);

		if (!fin.good()) throw std::string("\n***Could not open file***\n");
		
		fin.seekg(0, fin.end);
		nbytes = (int)fin.tellg();
		fin.seekg(0, fin.beg);

		// allocate memory here for the file content
		text = new char[nbytes];

		// read the content of the binary file
		fin.read(text, nbytes);

		fin.close();

		// end of STUDENT PORTION

		*ofs << "\n" << nbytes << " bytes copied from binary file "
			<< file << " into memory.\n";

		encoded = true;

		// decode using key
		code(key);

		*ofs << "Data decrypted in memory\n\n";
	}

	std::ostream& operator<<(std::ostream& os, const SecureData& sd) {
		sd.display(os);
		return os;
	}
}
