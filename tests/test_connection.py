"""
Discord DNS v3.5 — Contributor Diagnostic Suite: Connection Tester
Run: python -m tests.test_connection (or python tests/test_connection.py)
"""

import sys
import os
import time

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import dns_manager
import discord_checker
import dpi_bypass
import admin_utils

def run_tests():
    print("=" * 60)
    print("  DISCORD DNS v3.5 -- SYSTEM & CONNECTION DIAGNOSTIC TESTER")
    print("=" * 60)

    # Test 1: Admin privileges
    is_admin = admin_utils.is_admin()
    print(f"\n[1/5] Administrator Privileges: {'YES (Elevated)' if is_admin else 'NO (Normal User)'}")

    # Test 2: ISP Auto Detection
    print("\n[2/5] Testing ISP Auto-Detector...")
    start_time = time.time()
    isp_info = dpi_bypass.detect_isp()
    elapsed = (time.time() - start_time) * 1000
    print(f"  ISP Name        : {isp_info.get('isp')}")
    print(f"  Organization    : {isp_info.get('org')}")
    print(f"  Public IP       : {isp_info.get('ip')}")
    print(f"  Recommended Mode: {isp_info.get('recommended_channel')}")
    print(f"  Time Taken      : {int(elapsed)} ms")

    # Test 3: Adapter & DNS Discovery
    print("\n[3/5] Discovering Active Network Adapters...")
    adapters = dns_manager.get_network_adapters()
    print(f"  Active Adapters : {adapters}")
    if adapters:
        current_dns = dns_manager.get_current_dns(adapters[0])
        print(f"  Current DNS ({adapters[0]}):")
        print(f"    - IPv4: {current_dns.get('ipv4')}")
        print(f"    - IPv6: {current_dns.get('ipv6')}")
        print(f"    - Preset: {current_dns.get('preset_name')}")
        print(f"    - DHCP: {current_dns.get('is_dhcp')}")

    # Test 4: Primary Discord Endpoints Connectivity
    print("\n[4/5] Testing Primary Discord Endpoints...")
    disc_status = discord_checker.check_discord_connection()
    print(f"  Overall Status  : {'ACCESSIBLE' if disc_status['accessible'] else 'UNREACHABLE'}")
    print(f"  Average Ping    : {disc_status['ping_ms']} ms")
    for r in disc_status["host_results"]:
        print(f"    - {r}")

    # Test 5: Voice Regions Ping Matrix
    print("\n[5/5] Testing Voice Server Region Ping Matrix...")
    start_time = time.time()
    v_results = discord_checker.check_voice_regions()
    elapsed = (time.time() - start_time) * 1000
    print(f"  Matrix Completed in {int(elapsed)} ms:")
    for label, info in sorted(v_results.items(), key=lambda x: x[1]["ms"] if x[1]["ok"] else 9999):
        clean_label = label.split(" ", 1)[-1] if " " in label else label
        ping_str = f"{info['ms']} ms" if info["ok"] else "UNREACHABLE"
        print(f"    - {clean_label:<15}: {ping_str}")

    print("\n" + "=" * 60)
    print("  ALL DIAGNOSTIC TESTERS COMPLETED SUCCESSFULLY [OK]")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
