#pragma once

const int XOR_KEY{ 8 };
#include <vector>

const std::vector<LPVOID> VC_PREF_BASES{ (void*)0x00000000DDDD0000,
                                       (void*)0x0000000010000000,
                                       (void*)0x0000000021000000,
                                       (void*)0x0000000032000000,
                                       (void*)0x0000000043000000,
                                       (void*)0x0000000050000000,
                                       (void*)0x0000000041000000,
                                       (void*)0x0000000042000000,
                                       (void*)0x0000000040000000,
                                       (void*)0x0000000022000000 };