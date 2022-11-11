for i in range(1, 999)
    for u in range(1, 999)
        for y in range(1, 999)
            for t in range(1, 999)
                ip = i + "." + u + "." + y + "." + t
                router = get_router(ip)
                if router != null and router.firewall_rules != [] then
                    print(router.firewall_rules)
                end if
            end for
        end for
    end for
end for