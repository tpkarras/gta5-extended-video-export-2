#pragma once

#include <Windows.h>

#include <polyhook2/Detour/x64Detour.hpp>
#include <polyhook2/PE/IatHook.hpp>
#include <polyhook2/Virtuals/VFuncSwapHook.hpp>
#include <polyhook2/CapstoneDisassembler.hpp>
//#include "..\PolyHook\PolyHook\PolyHook.hpp"
#include "logger.h"

class VFuncDetour : public PLH::x64Detour
{
public:
	static std::unique_ptr<x64Detour> vDetour(void* func, uint_fast16_t vFuncIndex, void* funcHook, uint64_t tramp, PLH::ADisassembler& dis) {
		uint64_t func_p = reinterpret_cast<uint64_t>(func);
		uint64_t funcHook_p = (uint64_t)funcHook;
		return std::make_unique<x64Detour>((uint64_t)(func_p+vFuncIndex), funcHook_p, &tramp, dis);
	}
};

namespace {

	auto logger = std::make_shared<PolyHookLog>();
	std::vector<uint64_t> hookFuncTramps;
	std::vector<uint64_t> oOriginalVars;
	std::vector<uint64_t>::iterator it;
	int iterator = NULL;
	PLH::CapstoneDisassembler dis(PLH::Mode::x64);

	template <class CLASS_TYPE>
	HRESULT hookVirtualFunction(CLASS_TYPE* pInstance, int vFuncIndex, LPVOID hookFunc, std::shared_ptr<PLH::x64Detour> VFuncDetour_Ex) {
		it = hookFuncTramps.end();
		it = hookFuncTramps.insert(it, NULL);
		iterator = std::distance(hookFuncTramps.begin(), it);
			VFuncDetour_Ex = VFuncDetour::vDetour(pInstance, vFuncIndex, hookFunc, hookFuncTramps[iterator], dis);
		if (!VFuncDetour_Ex->hook()) {
			return E_FAIL;
		}
		return S_OK;
	}
	
	template <class = void>
	HRESULT hookNamedFunction(LPCSTR dllname, LPCSTR funcName, LPVOID hookFunc, std::shared_ptr<PLH::IatHook> IATHook_ex) {
		it = oOriginalVars.end();
		it = oOriginalVars.insert(it, NULL);
		iterator = std::distance(oOriginalVars.begin(), it);
		IATHook_ex.reset(new PLH::IatHook(dllname, funcName, (char*)hookFunc, &oOriginalVars[iterator], L""));
		if (!IATHook_ex->hook()) {
			return E_FAIL;
		}
		return S_OK;
	}

	template <class = void>
	HRESULT hookX64Function(LPVOID func, LPVOID hookFunc, std::shared_ptr<PLH::x64Detour> X64Detour_ex) {
		it = hookFuncTramps.end();
		it = hookFuncTramps.insert(it, NULL);
		iterator = std::distance(hookFuncTramps.begin(), it);
		X64Detour_ex.reset(new PLH::x64Detour((char*)func, (char*)hookFunc, &hookFuncTramps[iterator], dis));
		if (!X64Detour_ex->hook()) {
			return E_FAIL;
		}
		return S_OK;
	}
}