#pragma once
#include "math.h"
#include "decryption.h"
#include "..\driver\driver.hpp"


struct PlayerData {
    uintptr_t address;
    uintptr_t visualState;
    uintptr_t boneTransforms[20]; 
    Vector3 position;
    Vector3 bonePositions[20];  
    std::string name;
    bool isSleeping;
    bool isValid;
};

class BaseNetworkable {
public:
    static uintptr_t objects_basenetworkable(uintptr_t gameAssembly) {
        if (!gameAssembly) return 0;

        // Read BaseNetworkable TypeInfo
        uintptr_t typeInfo = driver::vulnerable()->get().read_physical_memory<uintptr_t>(gameAssembly + 0xD81AB88);
        if (!typeInfo) return 0;

        // Read static_fields from TypeInfo
        uintptr_t get_klass = driver::vulnerable()->get().read_physical_memory<uintptr_t>(typeInfo + 0xB8);
        if (!get_klass) return 0;

        // Read client_entities (0x10 from static_fields)
        uintptr_t client_entities = driver::vulnerable()->get().read_physical_memory<uintptr_t>(get_klass + 0x10);
        if (!client_entities) return 0;

        // Decrypt client_entities
        uintptr_t decrypt_list = Decrypt::BaseNetworkableKey(client_entities);
        if (!decrypt_list) return 0;

        // Read entity_list (0x10 from decrypted)
        uintptr_t entity_list = driver::vulnerable()->get().read_physical_memory<uintptr_t>(decrypt_list + 0x10);
        if (!entity_list) return 0;

        // Decrypt entity_list
        uintptr_t decrypt_ptr = Decrypt::DecryptList(entity_list);
        if (!decrypt_ptr) return 0;

        // Read buffer (0x10 from decrypted)
        uintptr_t result = driver::vulnerable()->get().read_physical_memory<uintptr_t>(decrypt_ptr + 0x10);
        return result;
    }

    static int size_basenetworkable(uintptr_t obj) {
        if (!obj) return 0;
        return driver::vulnerable()->get().read_physical_memory<int>(obj + static_cast<uintptr_t>(0x18));
    }

    static uintptr_t entity_basenetworkable(uintptr_t obj, int i) {
        if (!obj) return 0;
        uintptr_t data = driver::vulnerable()->get().read_physical_memory<uintptr_t>(obj + static_cast<uintptr_t>(0x10));
        if (!data) return 0;
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(data + 0x20 + (i * 8));
    }

    static std::string GetClassName(uintptr_t entity) {
        if (!entity) return "";
        uintptr_t pKlass = driver::vulnerable()->get().read_physical_memory<uintptr_t>(entity);
        if (!pKlass) return "";
        uintptr_t pName = driver::vulnerable()->get().read_physical_memory<uintptr_t>(pKlass + 0x10);
        if (!pName) return "";
        return driver::ReadChar(pName);
    }
};

class Camera {
public:
    static uintptr_t GetMainCamera(uintptr_t gameAssembly) {
        if (!gameAssembly) return 0;

        // Read static_fields from MainCamera class
        uintptr_t klass = driver::vulnerable()->get().read_chain<uintptr_t>(gameAssembly, { static_cast<uintptr_t>(0xD85FEB8), 0xB8 });
        if (!klass) return 0;

        // Read instance (0x90 from static_fields)
        uintptr_t cameraObj = driver::vulnerable()->get().read_physical_memory<uintptr_t>(klass + 0x90);
        if (!cameraObj) return 0;

        // Read buffer (0x10 from instance)
        uintptr_t result = driver::vulnerable()->get().read_physical_memory<uintptr_t>(cameraObj + 0x10);
        return result;
    }

    static Matrix GetViewMatrix(uintptr_t camera) {
        return driver::vulnerable()->get().read_physical_memory<Matrix>(camera + static_cast<uintptr_t>(0x30c));
    }
};

class BasePlayer {
public:
    uintptr_t address;
    BasePlayer(uintptr_t addr) : address(addr) {}

    uintptr_t GetVisualState() {
        if (!address) return 0;
        uintptr_t entityObject = driver::vulnerable()->get().read_physical_memory<uintptr_t>(address + 0x10);
        if (!entityObject) return 0;
        uintptr_t gameObject = driver::vulnerable()->get().read_physical_memory<uintptr_t>(entityObject + 0x30);
        if (!gameObject) return 0;
        uintptr_t entityClass = driver::vulnerable()->get().read_physical_memory<uintptr_t>(gameObject + 0x30);
        if (!entityClass) return 0;
        uintptr_t entityTransform = driver::vulnerable()->get().read_physical_memory<uintptr_t>(entityClass + 0x8);
        if (!entityTransform) return 0;
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(entityTransform + 0x38);
    }

    uintptr_t GetBoneTransforms() {
        if (!address) return 0;
        uintptr_t model = driver::vulnerable()->get().read_physical_memory<uintptr_t>(address + static_cast<uintptr_t>(0xe8));
        if (!model) return 0;
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(model + static_cast<uintptr_t>(0x50));
    }

    uintptr_t GetBoneTransform(uintptr_t boneTransforms, int id) {
        if (!boneTransforms) return 0;
        uintptr_t transform = driver::vulnerable()->get().read_physical_memory<uintptr_t>(boneTransforms + 0x20 + (id * 8));
        if (!transform) return 0;
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(transform + 0x38);
    }

    // Get head position - simple and reliable
    Vector3 GetHeadPosition() {
        if (!address) return { 0,0,0 };

        uintptr_t visualState = GetVisualState();
        if (!visualState) return { 0,0,0 };

        Vector3 pos = GetPosition(visualState);
        return Vector3(pos.x, pos.y + 1.6f, pos.z);
    }

    Vector3 GetPosition(uintptr_t visualState) {
        if (!visualState) return { 0,0,0 };
        return driver::vulnerable()->get().read_physical_memory<Vector3>(visualState + 0x90);
    }

    std::string GetName() {
        if (!address) return "";
        uintptr_t namePtr = driver::vulnerable()->get().read_physical_memory<uintptr_t>(address + static_cast<uintptr_t>(0x660));
        if (!namePtr || namePtr == UINTPTR_MAX || namePtr < 0x10000) return "";

        // Try direct read
        std::string name3 = driver::read_wstr(namePtr);
        if (!name3.empty() && name3.length() < 50) return name3;

        return "";
    }

    bool IsSleeping() {
        if (!address) return false;
        uint32_t flags = driver::vulnerable()->get().read_physical_memory<uint32_t>(address + static_cast<uintptr_t>(0x620));
        return (flags & 16);
    }

    bool IsWounded() {
        if (!address) return false;
        uint32_t flags = driver::vulnerable()->get().read_physical_memory<uint32_t>(address + static_cast<uintptr_t>(0x620));
        return (flags & 64);
    }

    bool IsAlive() {
        if (!address) return false;
        // Check lifestate (0 = alive, 1 = dead)
        uint8_t lifestate = driver::vulnerable()->get().read_physical_memory<uint8_t>(address + static_cast<uintptr_t>(0x268));
        return (lifestate == 0);
    }

    uint64_t GetTeam() {
        if (!address) return 0;
        return driver::vulnerable()->get().read_physical_memory<uint64_t>(address + static_cast<uintptr_t>(0x4b0));
    }

    // Get PlayerInput
    uintptr_t GetPlayerInput() {
        if (!address) return 0;
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(address + 0x350); // player_input offset 0x350
    }

    // Get/Set ViewAngles
    Vector3 GetViewAngles() {
        uintptr_t playerInput = GetPlayerInput();
        if (!playerInput) return { 0,0,0 };
        return driver::vulnerable()->get().read_physical_memory<Vector3>(playerInput + static_cast<uintptr_t>(0x44));
    }
    // Get PlayerEyes
    uintptr_t GetPlayerEyes() {
        if (!address) return 0;
        return driver::vulnerable()->get().read_physical_memory<uintptr_t>(address + 0x300); // player_eyes offset from new offsets
    }
};
