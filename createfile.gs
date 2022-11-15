CreateIfNotExist = function(type, path)
    computer = get_shell.host_computer
    file = computer.File(path)
    if file then
        exit("exists")
    else
        parsed_path = path.split("/")
        file_name = parsed_path[-1]
        parent_path = parsed_path
        parent_path.remove(-1)
        file_path = parent_path.join("/")

        if type == "file" then
            computer.touch(file_path, file_name)
        else
            computer.create_folder(file_path, file_name)
        end if
    end if
end function

CreateIfNotExist(params[0], params[1])