data = get_shell.host_computer.File(params[0]).get_content

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
        print("Clock : " + clock)
        print(i)
        if i == "" then
            clock = clock + 1
        else if i[0] == "*" then
            Vulns[clock].requirements.push(i.replace("* ", ""))
        end if
    end for

    print(Vulns)

    return Vulns
end function

ParseVulns(data)