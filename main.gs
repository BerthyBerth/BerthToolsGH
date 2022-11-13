IncludeLib = function(lib_name)
    _lib = include_lib("/lib/" + lib_name)
    if not _lib then _lib = include_lib(current_path + lib_name)
    if not _lib then exit("Library " + lib_name + " not found. Make sure to put it in /lib with this exact name.")

    return _lib
end function
metax = IncludeLib("metaxploit.so")
crypto = IncludeLib("crypto.so")

// Input IP
if params.len < 1 then exit("myprogram [ip/domain]")
    if params[0].split(".").len == 3 then
        ip = nslookup(params[0])
        if ip == "Not found" then exit("Domain not valid.")
    else
        ip = params[0]
end if
    
// Checking for victim's router
router = get_router(ip)
if not router then exit("Couldn't resolve victim's ip (" + ip + ")")
ports = []
for i in router.used_ports
    _port = {}
    _info = router.port_info(i).split(" ")
    _port.number = i.port_number
    _port.service = _info[0]
    _port.version = _info[1]
    _port.metalib = metax.net_use(ip, _port.number).dump_lib
    ports.push(_port)
end for

// Formating Visual Display
nb_max_len = 6
service_max_len = 7
version_max_len = 7

for i in ports
    // Port number length
    nb_port = (i.number + "").len
    if nb_port > nb_max_len then
        nb_max_len = nb_port + 2
    end if

    // Service number length
    nb_service = i.service.len
    if nb_service > service_max_len then
        service_max_len = nb_service + 2
    end if

    // Version number length
    nb_version = i.version.len
    if nb_version > version_max_len then
        version_max_len = nb_version + 2
    end if
end for

MainMenu = function()

    clear_screen()
    
    print("BSSID : " + router.bssid_name)
    print("ESSID : " + router.essid_name)
    print("Firewall rules : " + router.firewall_rules)

    print("")

    print(CreateBoard())

    print("")
    print("[1] Scan & save specific port vulns")
    print("[2] Use personnal computer data")
    print("[3] Exit")

    choice = user_input("Choice : ")

    if choice == "1" then
        ScanSpecificPortMenu()
    else if choice == "2" then
        UsePersonnalDataMenu()
    else if choice == "3" then
        exit("Bye bye")
    end if

end function

CreateBoard = function()
    board = "| INDEX | NUMBER"
    for i in range(0, nb_max_len - "number".len)
        board = board + " "
    end for
    board = board + "| SERVICE"
    for i in range(0, service_max_len - "service".len - 1)
        board = board + " "
    end for
    board = board + " | VERSION"
    for i in range(0, version_max_len - "version".len)
        board = board + " "
    end for
    board = board + "|"

    for i in range(0, ports.len - 1)

        line = "\n| " + (i + 1) + "     | "
        _port = ports[i]
        line = line + _port.number
        for u in range(0, nb_max_len - (_port.number + "").len - 1)
            line = line + " "
        end for

        line = line + " | " + _port.service
        for u in range(0, service_max_len - _port.service.len - 1)
            line = line + " "
        end for
        
        line = line + " | " + _port.version
        for u in range(0, version_max_len - _port.version.len - 1)
            line = line + " "
        end for

        board = board + line + " |"
        return board
    end for
end function

ParseVulns = function(data, memory)

    Vulns = []
    _start = []
    _end = []

    for i in range(0, data.len - 2)
        if data[i] == "<" and data[i + 1] == "b" and data[i + 2] == ">" then
            _start.push(i)
        end if
    end for

    for i in range(0, data.len - 3)
        if data[i] == "<" and data[i + 1] == "/" and data[i + 2] == "b" and data[i + 3] == ">" then
            _end.push(i)
        end if
    end for

    for i in range(0, _start.len - 1)
        value = ""
        for u in range(_start[i] + 3, _end[i] - 1)
            value = value + data[u]
        end for

        if value.split(".").len == 1 then
            _vuln = {}
            _vuln.memory = memory
            _vuln.value = value
            _vuln.requirements = []
            
            Vulns.push(_vuln)
        end if
    end for

    data = data.split("\n")
    data.remove(1)
    data.remove(0)
    
    clock = 0
    for i in data
        if i == "" then
            clock = clock + 1
        else if i[0] == "*" then
            Vulns[clock].requirements.push(i.replace("* ", ""))
        end if
    end for

    return Vulns
end function

WriteVuln = function(vuln, metalib, data)
    computer = get_shell.host_computer
    if not computer.File("/BerthTools") then computer.create_folder("/", "BerthTools")
    if not computer.File("/BerthTools/libs") then computer.create_folder("/BerthTools/", "libs")
    if not computer.File("/BerthTools/libs/" + metalib.lib_name) then computer.create_folder("/BerthTools/libs/", metalib.lib_name)
    if not computer.File("/BerthTools/libs/" + metalib.lib_name + "/" + metalib.version) then computer.create_folder("/BerthTools/libs/" + metalib.lib_name, metalib.version)
    if not computer.File("/BerthTools/libs/" + metalib.lib_name + "/" + metalib.version + "/" + vuln.memory) then computer.touch("/BerthTools/libs/" + metalib.lib_name + "/" + metalib.version, vuln.memory)
    computer.File("/BerthTools/libs/" + metalib.lib_name + "/" + metalib.version + "/" + vuln.memory).set_content(data)
    end function

UsePersonnalDataMenu = function()
    print(CreateBoard())

    port_index = user_input("\nTarget Port : ").to_int - 1
    file = get_shell.host_computer.File("/BerthTools/libs/" + ports[port_index].metalib.lib_name + "/" + ports[port_index].version)
    ChooseAddresses(ip, ports[port_index])
    wait(30)
    if (true) then
        print("Exists")
    else
        print("Not exists")
    end if
end function

ScanSpecificPortMenu = function()
    clear_screen()
    
    print(CreateBoard())

    index = user_input("\nIndex : ").to_int - 1
    ShowVulns(ip, ports[index])
end function

ChooseAddresses = function(ip, port)
    print("<b>VULNERABILITIES</b>")

    main_folder = get_shell.host_computer.File("/BerthTools/libs/" + port.metalib.lib_name + "/" + port.version)
    addresses = main_folder.get_files
    for i in range(0, addresses.len - 1)
        print("<b>[" + (i+1) + "]</b> " + addresses[i].name)
    end for

    choice = user_input("\nChoice : ").to_int - 1
    AddressVulnsMenu(addresses[choice], ip, port)
end function

AddressVulnsMenu = function(address_file, ip, port)
    clear_screen()

    print(CreateBoard())
    print()

    parsed_infos = ParseVulns(address_file.get_content, address_file.name) // Vuln Object Returns (vuln.memory, vuln.value, vuln.requirements)
    for i in range(0, parsed_infos.len - 1)
        print("<b>[" + (i+1) + "] " + parsed_infos[i].value + "</b>")
        for u in parsed_infos[i].requirements
            print(" * " + u)
        end for
    print("")
    end for
    choice = user_input("Choice : ").to_int - 1

    ExploitVuln(parsed_infos[choice].value, address_file.name, ip, port)
end function

AnalyseLib = function(index, router)
    net_session = metax.net_use(ip, ports[index].number)
    metalib = net_session.dump_lib

    addresses = metax.scan(metalib)
    for i in addresses
        data = metax.scan_address(metalib, i)
        parsed_data = ParseVulns(data, i)
        for u in parsed_data
            WriteVuln(u, metalib, data)
        end for
    end for

    user_input("\nENTER")
end function

ExploitVuln = function(value, address, ip, port)
    exploit = port.metalib.overflow(address, value, "1234")
    print(exploit)
    if typeof(exploit) == "shell" then exploit.start_terminal
end function

while true
    MainMenu()
end while