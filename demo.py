#! /usr/bin/env python3.8
from pyVim.connect import SmartConnect, SmartConnectNoSSL, Disconnect
from pyVmomi import vim
import json
import math
from pprint import pprint as dump


vsphere_hosts = ['1.1.1.1']
vsphere_password = '.....'
vsphere_username = '.....'


def main():
    esxi_hosts = []
    for vsphere_host in vsphere_hosts:
        serviceInstance = SmartConnectNoSSL(host=vsphere_host,
                                            user=vsphere_username,
                                            pwd=vsphere_password)
        content = serviceInstance.RetrieveContent()

        host_view = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.HostSystem], True)

        hosts = [host for host in host_view.view]
        for host in hosts:
            host_info = {}
            host_pnics = capture_host_pnics(host)
            host_vnics = capture_host_vnics(host)
            host_vswitches = capture_host_vswitches(host)
            host_portgroups = capture_host_portgroups(host)
            host_info.update(
                {'host': vsphere_host, 'hostname': host.name,
                 'pnics': host_pnics, 'vswitches': host_vswitches,
                 'portgroups': host_portgroups, 'vnics': host_vnics})
            host_info.update(capture_addon(serviceInstance));
            host_info.update(capture_vms(serviceInstance));
            esxi_hosts.append(host_info)

        Disconnect(serviceInstance)

    dump(esxi_hosts);
    print(json.dumps(esxi_hosts, indent=4))


def capture_host_pnics(host):
    host_pnics = {}
    for pnic in host.config.network.pnic:
        pnic_info = dict()
        pnic_info.update(
            {'device': pnic.device, 'driver': pnic.driver, 'mac': pnic.mac})
        host_pnics.update({ pnic.device: pnic_info })

    return host_pnics


def capture_host_vnics(host):
    host_vnics = []
    for vnic in host.config.network.vnic:
        vnic_info = dict()
        vnic_info.update(
            {
             'device': vnic.device, 'portgroup': vnic.portgroup,
             'dhcp': vnic.spec.ip.dhcp, 'ipAddress': vnic.spec.ip.ipAddress,
             'subnetMask': vnic.spec.ip.subnetMask,
             'mac': vnic.spec.mac, 'mtu': vnic.spec.mtu})
        host_vnics.append(vnic_info)
    return host_vnics


def capture_host_vswitches(host):
    host_vswitches = {}
    for vswitch in host.config.network.vswitch:
        vswitch_info = dict()
        vswitch_pnics = []
        vswitch_portgroups = []
        for pnic in vswitch.pnic:
            pnic = pnic.replace('key-vim.host.PhysicalNic-', '')
            vswitch_pnics.append(pnic)
        for pg in vswitch.portgroup:
            pg = pg.replace('key-vim.host.PortGroup-', '')
            vswitch_portgroups.append(pg)
        vswitch_info.update(
            {'name': vswitch.name, 'pnics': vswitch_pnics,
             'portgroups': vswitch_portgroups, 'mtu': vswitch.mtu})
        host_vswitches.update({ vswitch.name: vswitch_info })

    return host_vswitches


def capture_host_portgroups(host):
    host_portgroups = {}
    for portgroup in host.config.network.portgroup:
        portgroup_info = {}
        portgroup_info.update(
            {'name': portgroup.spec.name, 'vlanId': portgroup.spec.vlanId,
             'vswitchName': portgroup.spec.vswitchName,
             'nicTeamingPolicy': portgroup.spec.policy.nicTeaming.policy,
             'allowPromiscuous': portgroup.spec.policy.security.allowPromiscuous,
             'macChanges': portgroup.spec.policy.security.macChanges,
             'forgedTransmits': portgroup.spec.policy.security.forgedTransmits})
        host_portgroups.update({ portgroup.spec.name: portgroup_info })

    return host_portgroups


def capture_addon(serviceInstance):

    def get_servers(serviceInstance):
        def convertMemory(sizeBytes):
            name = ("B", "KB", "MB", "GB", "TB", "PB")
            base = int(math.floor(math.log(sizeBytes, 1024)))
            power = math.pow(1024,base)
            size = round(sizeBytes/power,2)
            return "{}{}".format(math.floor(size),name[base])

        content = serviceInstance.RetrieveContent()
        hosts = content.viewManager.CreateContainerView(content.rootFolder,[vim.HostSystem],True)
        cpus = {}
        for host in hosts.view:
            cpu = {}
            print(host)
            cpu.update({
                            'name': str(host),
                            'vendor': host.hardware.systemInfo.vendor,
                            'model': host.hardware.systemInfo.model,
                            'uuid': host.hardware.systemInfo.uuid,
                            'cpuPkg': [ host.hardware.cpuPkg[0].description, host.hardware.cpuPkg[1].description ],
                            'memorySize': host.hardware.memorySize,
                            'biosInfo': {
                                          'biosVersion':  host.hardware.biosInfo.biosVersion,
                                          'releaseDate':  str(host.hardware.biosInfo.releaseDate),
                                          'vendor':       host.hardware.biosInfo.vendor,
                                          'majorRelease': host.hardware.biosInfo.majorRelease,
                                          'minorRelease': host.hardware.biosInfo.minorRelease
                                        },
                             'numCpuPackage': host.hardware.cpuInfo.numCpuPackages,
                             'numCpuCores': host.hardware.cpuInfo.numCpuCores,
                             'numCpuThreads': host.hardware.cpuInfo.numCpuThreads,
                             'hz': host.hardware.cpuInfo.hz,
                             'Ghz':  round(((host.hardware.cpuInfo.hz/1e+9)*host.hardware.cpuInfo.numCpuCores),0),
                             'Memory': convertMemory(host.hardware.memorySize)
                            })

            cpus.update( { host: cpu });
        return cpu

    def get_disk(serviceInstance):
        content = serviceInstance.RetrieveContent()

        def sizeof_fmt(num):
            for item in ['bytes', 'KB', 'MB', 'GB']:
                if num < 1024.0:
                    return "%3.1f%s" % (num, item)
                num /= 1024.0
            return "%3.1f%s" % (num, 'TB')

        def get_obj_disk(content, vim_type):
            obj = {}
            container = content.viewManager.CreateContainerView(
                content.rootFolder, vim_type, True)
            for c in container.view:
                obj.update({c.name: c });
            return obj

        def print_datastore_info(ds_obj):
            summary = ds_obj.summary
            ds_capacity = summary.capacity
            ds_freespace = summary.freeSpace
            ds_uncommitted = summary.uncommitted if summary.uncommitted else 0
            ds_provisioned = ds_capacity - ds_freespace + ds_uncommitted
            ds_overp = ds_provisioned - ds_capacity
            ds_overp_pct = (ds_overp * 100) / ds_capacity  if ds_capacity else 0
            obj = {
                    "TYPE": summary.type,
                    "NAME": summary.name,
                    "URL":  summary.url ,
                    "Capacity Gb":    sizeof_fmt(ds_capacity)   ,
                    "Free Space Gb":  sizeof_fmt(ds_freespace)  ,
                    "Uncommitted Gb": sizeof_fmt(ds_uncommitted),
                    "Provisioned Gb": sizeof_fmt(ds_provisioned),
                    "Capacity":    ds_capacity   ,
                    "Free Space":  ds_freespace  ,
                    "Uncommitted": ds_uncommitted,
                    "Provisioned": ds_provisioned,
                    "Hosts":            len(ds_obj.host),
                    "Virtual Machines": len(ds_obj.vm)
                  };
            return obj

        ds_obj_list = get_obj_disk(content, [vim.Datastore])
        disk = {};
        for name,ds in ds_obj_list.items():
            disk.update({ name: print_datastore_info(ds)});
        return disk

    def get_vlan(serviceInstance):
        datacenters = serviceInstance.RetrieveContent().rootFolder.childEntity
        switch = {}
        for datacenter in datacenters:
            hosts = datacenter.hostFolder.childEntity
            for host in hosts:
                networks = host.network
                for network in networks:
                    vlan = []
                    for i in network.vm:
                        vlan.append(str(i));
                    switch.update({ str(network.name) : vlan });
        return switch
    return { "servers": get_servers(serviceInstance), "datastore": get_disk(serviceInstance), "vlan": get_vlan(serviceInstance) };


def capture_vms(serviceInstance):
    def GetVMHosts(content):
        host_view = content.viewManager.CreateContainerView(content.rootFolder,
                                                            [vim.HostSystem],
                                                            True)
        obj = [host for host in host_view.view]
        host_view.Destroy()
        return obj
    def GetVMs(content):
        vm_view = content.viewManager.CreateContainerView(content.rootFolder,
                                                          [vim.VirtualMachine],
                                                          True)
        obj = [vm for vm in vm_view.view]
        vm_view.Destroy()
        return obj
    def GetHostsPortgroups(hosts):
        hostPgDict = {}
        for host in hosts:
            pgs = host.config.network.portgroup
            hostPgDict[host] = pgs
        return hostPgDict
    def PrintVmInfo(vm,hosts,hostPgDict,content):
        vmPowerState = vm.runtime.powerState
        summary = vm.summary
        config = vm.config

        obj = {
                   "VMID":      str(vm),           "VM": str(vm.name),        "vmPowerState": vmPowerState,
                   "FULL Name": config.guestFullName,  "guestId": config.guestId, "mPathName":config.files.vmPathName,
                   "numCPU":    config.hardware.numCPU,"numCoresPerSocket": config.hardware.numCoresPerSocket,
                   "memory GB": config.hardware.memoryMB/1024,
                   "memory":    config.hardware.memoryMB,
                   "suspendTime":    str(vm.runtime.suspendTime),
                   "bootTime":       str(vm.runtime.bootTime),
                   "suspendInterval":vm.runtime.suspendInterval,
                   "question":       vm.runtime.question,
                   "memoryOverhead": vm.runtime.memoryOverhead,
                   "maxCpuUsage":    vm.runtime.maxCpuUsage,
                   "maxMemoryUsage": vm.runtime.maxMemoryUsage,
               }
        device = []
        for i in config.hardware.device:
            t = type(i).__name__
            if t=='vim.vm.device.VirtualVmxnet3':
                 device.append({ 'type': 'VirtualVmxnet3', "label": i.deviceInfo.label, "summary": i.deviceInfo.summary });
            elif t=='vim.vm.device.VirtualPCIPassthrough':
                 device.append({ 'type': 'VirtualPCIPassthrough', "label": i.deviceInfo.label,
                                 "id": i.backing.id, "deviceId": i.backing.deviceId
                                });
            elif t=='vim.vm.device.VirtualE1000e':
                 device.append( { 'type': 'VirtualE1000e', "label": i.deviceInfo.label, "summary": i.deviceInfo.summary });
            elif t=='vim.vm.device.VirtualDisk':
                 device.append({
                          'type':        'VirtualDisk',
                          "label":       i.deviceInfo.label,
                          "capacity":    i.capacityInBytes,
                          "capacity GB": i.capacityInBytes/1024/1024/1024,
                          "fileName":    i.backing.fileName
                        });
            elif t=='vim.vm.device.VirtualCdrom':
                 device.append({ 'type': 'VirtualCdrom', "label": i.deviceInfo.label, "summary": i.deviceInfo.summary });
            elif t=='vim.vm.device.VirtualLsiLogicController':
                 device.append({ 'type': 'VirtualLsiLogicController', "label": i.deviceInfo.label, "summary": i.deviceInfo.summary });
            elif t=='vim.vm.device.VirtualAHCIController':
                 device.append({ 'type': 'VirtualAHCIController', "label": i.deviceInfo.label, "summary": i.deviceInfo.summary});
        obj.update({ 'device': device });

        annotation = summary.config.annotation

        obj.update({ "network": GetVMNics(vm,hosts,hostPgDict,content) });
        return obj;

    def GetVMNics(vm,hosts,hostPgDict,content):
        vnic = []
        for dev in vm.config.hardware.device:
            if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                dev_backing = dev.backing
                portGroup = None
                vlanId = None
                vSwitch = None
                if hasattr(dev_backing, 'port'):
                    portGroupKey = dev.backing.port.portgroupKey
                    dvsUuid = dev.backing.port.switchUuid
                    try:
                        dvs = content.dvSwitchManager.QueryDvsByUuid(dvsUuid)
                    except:
                        portGroup = "** Error: DVS not found **"
                        vlanId = "NA"
                        vSwitch = "NA"
                    else:
                        pgObj = dvs.LookupDvPortGroup(portGroupKey)
                        portGroup = pgObj.config.name
                        vlanId = str(pgObj.config.defaultPortConfig.vlan.vlanId)
                        vSwitch = str(dvs.name)
                else:
                    portGroup = dev.backing.network.name
                    vmHost = vm.runtime.host
                    host_pos = hosts.index(vmHost)
                    viewHost = hosts[host_pos]
                    pgs = hostPgDict[viewHost]
                    for p in pgs:
                        if portGroup in p.key:
                            vlanId = str(p.spec.vlanId)
                            vSwitch = str(p.spec.vswitchName)
                if portGroup is None:
                    portGroup = 'NA'
                if vlanId is None:
                    vlanId = 'NA'
                if vSwitch is None:
                    vSwitch = 'NA'
                vnic.append({ 'label': dev.deviceInfo.label , 'macAddress': dev.macAddress , 'vSwitch': vSwitch , 'portGroup': portGroup, 'vlanId': vlanId });
        return vnic

    def get_vm( serviceInstance ):
        content = serviceInstance.RetrieveContent()
        hosts = GetVMHosts(content)
        hostPgDict = GetHostsPortgroups(hosts)
        vms = GetVMs(content)
        cloud = {}
        for vm in vms:
            cloud.update({ str(vm): PrintVmInfo(vm,hosts,hostPgDict,content) });
        return cloud

    return {"VM": get_vm(serviceInstance) }



if __name__ == "__main__":
    main()
