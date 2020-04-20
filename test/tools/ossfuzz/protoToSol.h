/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include <test/tools/ossfuzz/solProto.pb.h>

#include <random>
#include <string>
#include <utility>
#include <variant>

namespace solidity::test::solprotofuzzer
{
/// Random number generator that is seeded with a fuzzer
/// supplied unsigned integer.
struct SolRandomNumGenerator
{
	using RandomEngine = std::minstd_rand;

	explicit SolRandomNumGenerator(unsigned _seed): m_random(RandomEngine(_seed)) {}

	/// @returns a pseudo random unsigned integer
	unsigned operator()()
	{
		return m_random();
	}

	RandomEngine m_random;
};

class ProtoConverter
{
public:
	ProtoConverter() {}
	ProtoConverter(ProtoConverter const&) = delete;
	ProtoConverter(ProtoConverter&&) = delete;
	std::string protoToSolidity(Program const&);
	/// @returns true if test calls a library function, false
	/// otherwise
	bool libraryTest() const;
	/// @returns name of the library under test
	std::string libraryName() const;
private:
	/// Variant type that points to one of contract, interface, library protobuf messages
	using CIL = std::variant<Contract const*, Interface const*, Library const*>;
	/// Protobuf message visitors that accept a const reference to a protobuf message
	/// type and return its solidity translation.
	std::string visit(Program const&);
	std::string visit(TestContract const&);
	std::string visit(ContractType const&);
	std::string visit(Interface const& _interface);
	std::string visit(Library const& _library);
	std::string visit(Contract const& _contract);
	/// @returns a string pair containing a library declaration (relevant for library
	/// tests only) and a solidity test case
	std::pair<std::string, std::string> generateTestCase(TestContract const& _testContract);
	/// @returns name of a program i.e., contract, library or interface
	std::string programName(CIL _program);
	/// @returns a tuple containing the names of the library and function under
	/// test, and its expected output.
	std::tuple<std::string, std::string, std::string> pseudoRandomLibraryTest();
	/// Performs bookkeeping for a fuzzer-supplied program
	void openProgramScope(CIL _program);
	/// @returns a deterministic pseudo random unsigned integer
	unsigned randomNumber();
	/// @returns true if fuzzer supplied Library protobuf message
	/// contains zero functions, false otherwise.
	static bool emptyLibrary(Library const& _library)
	{
		return _library.funcdef_size() == 0;
	}
	/// @returns true if there are no valid library test cases, false
	/// otherwise.
	bool emptyLibraryTests()
	{
		return m_libraryTests.size() == 0;
	}
	/// @returns true if there are no valid contract test cases, false
	/// otherwise.
	bool emptyContractTests()
	{
		return m_contractTests.size() == 0;
	}
	/// Numeric suffix that is part of program names e.g., "0" in "C0"
	unsigned m_programNumericSuffix = 0;
	/// Flag that states whether library call is tested (true) or not (false).
	bool m_libraryTest = false;
	/// A smart pointer to fuzzer driven random number generator
	std::shared_ptr<SolRandomNumGenerator> m_randomGen;
	/// Maps const pointer to protobuf program to its string name
	std::map<CIL, std::string> m_programNameMap;
	/// List of tuples containing library name, function and its expected output
	std::vector<std::tuple<std::string, std::string, std::string>> m_libraryTests;
	/// Maps contract name to a map of function names and their expected output
	std::map<std::string, std::map<std::string, std::string>> m_contractTests;
	/// Name of the library under test, relevant if m_libraryTest is set
	std::string m_libraryName;
	/// Maximum number of local variables in test function to avoid stack too deep
	/// errors
	static unsigned constexpr s_maxVars = 15;
};
}