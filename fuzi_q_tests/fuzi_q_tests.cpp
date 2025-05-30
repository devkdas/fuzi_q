#include "pch.h"
#include "CppUnitTest.h"
#include "fuzi_q_tests.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace fuziqtests
{
	TEST_CLASS(fuziqtests)
	{
	public:
		
		TEST_METHOD(basic)
		{
			int ret = fuzi_q_basic_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(basic_client)
		{
			int ret = fuzi_q_basic_client_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(icid_table)
		{
			int ret = icid_table_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(FrameAckInvalidGap1)
		{
			int ret = test_frame_ack_invalid_gap_1();
			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(FrameConnectionCloseFrameEncodingError)
		{
			int ret = test_frame_connection_close_frame_encoding_error();
			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(GranularPadding)
		{
			int ret = test_granular_padding();
			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(FrameSequence)
		{
			int ret = test_frame_sequence();
			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(ErrorConditions)
		{
			int ret = test_error_conditions();
			Assert::AreEqual(ret, 0);
		}
	};
}
