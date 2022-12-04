#pragma once

#include <Windows.h>

#include <polyhook2/Detour/x64Detour.hpp>
#include <polyhook2/PE/IatHook.hpp>
#include <polyhook2/Virtuals/VFuncSwapHook.hpp>
#include <polyhook2/CapstoneDisassembler.hpp>
//#include "..\PolyHook\PolyHook\PolyHook.hpp"
#include "logger.h"

namespace {

	auto logger = std::make_shared<PolyHookLog>();
	uint64_t hookFuncTramp;
	uint64_t VHookFuncTramp;
	uint64_t oOriginalVar;

	template <class CLASS_TYPE>
	HRESULT hookVirtualFunction(CLASS_TYPE *pInstance, int vFuncIndex, LPVOID hookFunc, std::shared_ptr<PLH::x64Detour> VFuncDetour_Ex) {
		PLH::CapstoneDisassembler dis(PLH::Mode::x64);
		VFuncDetour_Ex = std::make_unique<PLH::x64Detour>(*(char*)(pInstance+vFuncIndex), (uint64_t)hookFunc, &VHookFuncTramp, dis));
		if (!VFuncDetour_Ex->hook()) {
			return E_FAIL;
		}
		return S_OK;
	}
	
	template <class = void>
	HRESULT hookNamedFunction(LPCSTR dllname, LPCSTR funcName, LPVOID hookFunc, std::shared_ptr<PLH::IatHook> IATHook_ex) {
		IATHook_ex.reset(new PLH::IatHook(dllname, funcName, (char*)hookFunc, &oOriginalVar, L""));
		if (!IATHook_ex->hook()) {
			return E_FAIL;
		}
		return S_OK;
	}

	template <class = void>
	HRESULT hookX64Function(LPVOID func, LPVOID hookFunc, std::shared_ptr<PLH::x64Detour> X64Detour_ex) {
		PLH::CapstoneDisassembler dis(PLH::Mode::x64);
		X64Detour_ex.reset(new PLH::x64Detour((char*)func, (char*)hookFunc, &hookFuncTramp, dis));
		if (!X64Detour_ex->hook()) {
			return E_FAIL;
		}
		return S_OK;
	}
}