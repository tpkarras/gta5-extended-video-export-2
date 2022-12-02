#pragma once

#include <Windows.h>

#include <polyhook2/Detour/x64Detour.hpp>
#include <polyhook2/PE/IatHook.hpp>
#include <polyhook2/Virtuals/VFuncSwapHook.hpp>
#include <polyhook2/CapstoneDisassembler.hpp>
//#include "..\PolyHook\PolyHook\PolyHook.hpp"
#include "logger.h"

namespace {

	extern uint64_t hookFuncTramp = NULL;

	template <class CLASS_TYPE>
	HRESULT hookVirtualFunction(CLASS_TYPE* pInstance, int vFuncIndex, LPVOID hookFunc, std::shared_ptr<PLH::VFuncSwapHook> VFuncDetour_Ex) {
		PLH::VFuncMap * VFuncDetour_ExOrigMaps = new PLH::VFuncMap;
		PLH::VFuncMap VFuncDetour_ExMaps = { {(uint16_t)vFuncIndex, (uint64_t)hookFunc} };
		VFuncDetour_Ex.reset(new PLH::VFuncSwapHook((uint64_t)pInstance, (PLH::VFuncMap)VFuncDetour_ExMaps, (PLH::VFuncMap *)VFuncDetour_ExOrigMaps));
		if (!VFuncDetour_Ex->hook()) {
			LOG(LL_ERR, new PLH::Error);
			return E_FAIL;
		}
		if (VFuncDetour_ExOrigMaps->size() < 1) {
			LOG(LL_ERR, new PLH::Error);
			return E_FAIL;
		}
		return S_OK;
	}
	
	template <class = void>
	HRESULT hookNamedFunction(LPCSTR dllname, LPCSTR funcName, LPVOID hookFunc, std::shared_ptr<PLH::IatHook> IATHook_ex) {
		uint64_t oOriginalVar = NULL;
		IATHook_ex.reset(new PLH::IatHook(dllname, funcName, (char*)hookFunc, &oOriginalVar, L""));
		if (!IATHook_ex->hook()) {
			LOG(LL_ERR, new PLH::Error);
			return E_FAIL;
		}
		return S_OK;
	}

	template <class = void>
	HRESULT hookX64Function(LPVOID func, LPVOID hookFunc, std::shared_ptr<PLH::x64Detour> X64Detour_ex) {
		X64Detour_ex.reset(new PLH::x64Detour((uint16_t)func, (uint16_t)hookFunc, &hookFuncTramp, PLH::CapstoneDisassembler(PLH::Mode::x64)));
		if (!X64Detour_ex->hook()) {
			LOG(LL_ERR, new PLH::Error);
			return E_FAIL;
		}
		return S_OK;
	}
}