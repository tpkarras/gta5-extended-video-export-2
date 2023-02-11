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
	PLH::CapstoneDisassembler dis(PLH::Mode::x64);

	template <class CLASS_TYPE, class FUNC_TYPE>
	HRESULT hookVirtualFunction(CLASS_TYPE* pInstance, uint16_t vFuncIndex, LPVOID hookFunc, FUNC_TYPE* originalFunc, std::shared_ptr<PLH::VFuncSwapHook> VFuncSwapHook_Ex) {
		const PLH::VFuncMap hookMap = { {vFuncIndex, reinterpret_cast<uint64_t>(hookFunc)} };
		PLH::VFuncMap originalFunctions;
		VFuncSwapHook_Ex.reset(new PLH::VFuncSwapHook(reinterpret_cast<uint64_t>(pInstance), hookMap, &originalFunctions));
		if (!VFuncSwapHook_Ex->hook()) {
			return E_FAIL;
		}
		*originalFunc = ForceCast<FUNC_TYPE, uint64_t>(originalFunctions[vFuncIndex]);
		return S_OK;
	}
	
	template <class FUNC_TYPE>
	HRESULT hookNamedFunction(LPCSTR dllname, LPCSTR funcName, LPVOID hookFunc, FUNC_TYPE* originalVar, std::shared_ptr<PLH::IatHook> IATHook_ex) {
		IATHook_ex.reset(new PLH::IatHook(dllname, funcName, reinterpret_cast<uint64_t>(hookFunc), reinterpret_cast<uint64_t*>(&originalVar), L""));
		if (!IATHook_ex->hook()) {
			return E_FAIL;
		}
		return S_OK;
	}

	template <class = void>
	HRESULT hookX64Function(LPVOID func, LPVOID hookFunc, uint64_t tramp, std::shared_ptr<PLH::x64Detour> X64Detour_ex) {
		X64Detour_ex.reset(new PLH::x64Detour((char*)func, (char*)hookFunc, &tramp, dis));
		if (!X64Detour_ex->hook()) {
			return E_FAIL;
		}
		return S_OK;
	}
}