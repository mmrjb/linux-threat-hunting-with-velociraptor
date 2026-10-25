# LTH - 05 - Network Connections Dashboard

Ordered notebook cell inputs. This file and its companion JSON are source templates, not a native Velociraptor import archive. Replace HUNT_ID with the ID of the appropriate hunt in your own environment.

## Cell 1 (markdown)

# LTH - 05 - Network Connections Dashboard

This notebook analyzes Linux network connection data collected by:

`LTH.NetworkConnections`

Main objectives:

- Review listening ports across Linux endpoints
- Review established network connections
- Correlate network activity with process information
- Identify suspicious ports and suspicious network tools
- Review routing table, DNS configuration, and firewall rules
- Detect possible backdoors, C2 communication, lateral movement, or exfiltration paths
- Prioritize clients that need deeper investigation

## Cell 2 (markdown)

# Listening Ports Inventory

Normalized and deduplicated inventory of TCP listening sockets across Linux endpoints, including address scope and responsible process context. This cell provides investigation context only and does not generate findings or contribute to the Master Risk Score.

## Cell 3 (vql)

```vql
-- ============================================================
-- Listening Ports Inventory
-- Role: Inventory / Investigation Context
-- Risk Score Eligible: No
-- ============================================================

LET HuntId <= "HUNT_ID"


LET ListeningRaw <=
    SELECT
        ClientId,
        client_info(client_id=ClientId).os_info.fqdn AS Fqdn,
        Status,
        Laddr AS LocalAddress,
        Lport AS LocalPort,
        Pid,
        ProcInfo.Name AS ProcessName,
        ProcInfo.Exe AS ProcessPath,
        ProcInfo.Username AS Username,
        ProcInfo.CommandLine AS CommandLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ "(?i)^LISTEN$"


LET ListeningNormalized <=
    SELECT
        ClientId,
        Fqdn,

        "TCP" AS Transport,

        if(
            condition=LocalAddress =~ ":",
            then="IPv6",
            else="IPv4"
        ) AS AddressFamily,

        Status,
        LocalAddress,
        LocalPort,
        Pid,
        ProcessName,
        ProcessPath,
        Username,
        CommandLine,

        if(
            condition=LocalAddress =~ "^127[.]" OR LocalAddress = "::1",
            then="LOOPBACK_ONLY",

            else=if(
                condition=LocalAddress = "0.0.0.0",
                then="ALL_INTERFACES",

                else=if(
                    condition=LocalAddress = "::",
                    then="IPV6_ALL_INTERFACES",
                    else="SPECIFIC_INTERFACE"
                )
            )
        ) AS BindingScope,

        format(
            format="%v|TCP|%v|%v|%v",
            args=[
                ClientId,
                LocalAddress,
                LocalPort,
                Pid
            ]
        ) AS ListenerKey

    FROM ListeningRaw


SELECT
    ClientId,
    Fqdn,
    Transport,
    AddressFamily,
    Status,
    LocalAddress,
    LocalPort,
    BindingScope,
    Pid,
    ProcessName,
    ProcessPath,
    Username,
    CommandLine,
    ListenerKey

FROM ListeningNormalized

GROUP BY ListenerKey

ORDER BY
    ClientId
```

## Cell 4 (markdown)

# Listening Port Exposure Summary per Client

Deduplicated exposure summary of TCP listening sockets per client, separated by binding scope, port range, and process attribution. This cell provides baseline context only and does not generate findings or contribute to the Master Risk Score.

## Cell 5 (vql)

```vql
-- ============================================================
-- Listening Port Exposure Summary per Client
-- Role: Baseline / Exposure Summary
-- Risk Score Eligible: No
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- 1. Normalize listening-socket records
-- ------------------------------------------------------------

LET ListeningNormalized <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Laddr AS LocalAddress,
        Lport AS LocalPort,
        Pid,
        ProcInfo.Name AS ProcessName,

        if(
            condition=Laddr =~ '''^127[.]''' OR Laddr = "::1",
            then="LOOPBACK_ONLY",

            else=if(
                condition=Laddr = "0.0.0.0",
                then="ALL_INTERFACES",

                else=if(
                    condition=Laddr = "::",
                    then="IPV6_ALL_INTERFACES",
                    else="SPECIFIC_INTERFACE"
                )
            )
        ) AS BindingScope,

        format(
            format="%v|TCP|%v|%v|%v",
            args=[
                ClientId,
                Laddr,
                Lport,
                Pid
            ]
        ) AS ListenerKey

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ '''(?i)^LISTEN$'''


-- ------------------------------------------------------------
-- 2. Remove exact duplicate listener records
-- ------------------------------------------------------------

LET ListeningDeduplicated <=
    SELECT
        ClientId,
        Fqdn,
        LocalAddress,
        LocalPort,
        Pid,
        ProcessName,
        BindingScope,
        ListenerKey

    FROM ListeningNormalized

    GROUP BY ListenerKey


-- ------------------------------------------------------------
-- 3. Aggregate exposure metrics per client
-- ------------------------------------------------------------

LET ExposureSummary <=
    SELECT
        ClientId,
        Fqdn,

        count() AS ListeningSocketCount,

        sum(
            item=if(
                condition=BindingScope = "LOOPBACK_ONLY",
                then=1,
                else=0
            )
        ) AS LoopbackOnlySocketCount,

        sum(
            item=if(
                condition=BindingScope = "ALL_INTERFACES"
                          OR BindingScope = "IPV6_ALL_INTERFACES",
                then=1,
                else=0
            )
        ) AS AllInterfaceSocketCount,

        sum(
            item=if(
                condition=BindingScope = "SPECIFIC_INTERFACE",
                then=1,
                else=0
            )
        ) AS SpecificInterfaceSocketCount,

        sum(
            item=if(
                condition=BindingScope != "LOOPBACK_ONLY",
                then=1,
                else=0
            )
        ) AS PotentiallyNetworkExposedSocketCount,

        sum(
            item=if(
                condition=LocalPort < 1024,
                then=1,
                else=0
            )
        ) AS PrivilegedPortSocketCount,

        sum(
            item=if(
                condition=LocalPort >= 1024,
                then=1,
                else=0
            )
        ) AS HighNumberedPortSocketCount,

        sum(
            item=if(
                condition=Pid > 0 OR ProcessName,
                then=1,
                else=0
            )
        ) AS AttributedSocketCount,

        sum(
            item=if(
                condition=NOT (Pid > 0 OR ProcessName),
                then=1,
                else=0
            )
        ) AS UnattributedSocketCount

    FROM ListeningDeduplicated

    GROUP BY
        ClientId,
        Fqdn


-- ------------------------------------------------------------
-- 4. Final baseline summary with count validation
-- ------------------------------------------------------------

SELECT
    ClientId,
    Fqdn,
    ListeningSocketCount,
    LoopbackOnlySocketCount,
    AllInterfaceSocketCount,
    SpecificInterfaceSocketCount,
    PotentiallyNetworkExposedSocketCount,
    PrivilegedPortSocketCount,
    HighNumberedPortSocketCount,
    AttributedSocketCount,
    UnattributedSocketCount,

    if(
        condition=
            ListeningSocketCount =
                LoopbackOnlySocketCount +
                AllInterfaceSocketCount +
                SpecificInterfaceSocketCount

            AND

            ListeningSocketCount =
                PrivilegedPortSocketCount +
                HighNumberedPortSocketCount

            AND

            ListeningSocketCount =
                AttributedSocketCount +
                UnattributedSocketCount,

        then="PASS",
        else="CHECK"
    ) AS CountValidation,

    FALSE AS RiskScoreEligible

FROM ExposureSummary

ORDER BY
    PotentiallyNetworkExposedSocketCount DESC
```

## Cell 6 (markdown)

# Established Connections Inventory

Normalized and deduplicated inventory of established TCP connections across Linux endpoints, including local and remote endpoints, destination scope, and responsible process context. This cell provides investigation context only and does not generate findings or contribute to the Master Risk Score.

## Cell 7 (vql)

```vql
-- ============================================================
-- Established Connections Inventory
-- Role: Inventory / Investigation Context
-- Risk Score Eligible: No
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- 1. Collect established connections
-- ------------------------------------------------------------

LET EstablishedRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Status,

        Laddr AS LocalAddress,
        Lport AS LocalPort,

        Raddr AS RemoteAddress,
        Rport AS RemotePort,

        Pid,
        ProcInfo.Name AS ProcessName,
        ProcInfo.Exe AS ProcessPath,
        ProcInfo.Username AS Username,
        ProcInfo.CommandLine AS CommandLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ '''(?i)^(ESTAB|ESTABLISHED)$'''


-- ------------------------------------------------------------
-- 2. Normalize connection context
-- ------------------------------------------------------------

LET EstablishedNormalized <=
    SELECT
        ClientId,
        Fqdn,

        "TCP" AS Transport,

        if(
            condition=RemoteAddress =~ '''(?i)^::ffff:''',
            then="IPv4_MAPPED_IPV6",

            else=if(
                condition=RemoteAddress =~ ":",
                then="IPv6",
                else="IPv4"
            )
        ) AS AddressFamily,

        "ESTABLISHED" AS ConnectionState,

        LocalAddress,
        LocalPort,
        RemoteAddress,
        RemotePort,

        if(
            condition=NOT RemoteAddress OR RemoteAddress = "",
            then="UNKNOWN",

            else=if(
                condition=
                    RemoteAddress =~ '''(?i)^(::ffff:)?127[.]'''
                    OR RemoteAddress = "::1",

                then="LOOPBACK",

                else=if(
                    condition=
                        RemoteAddress =~ '''(?i)^(::ffff:)?10[.]'''
                        OR RemoteAddress =~
                            '''(?i)^(::ffff:)?172[.](1[6-9]|2[0-9]|3[01])[.]'''
                        OR RemoteAddress =~
                            '''(?i)^(::ffff:)?192[.]168[.]'''
                        OR RemoteAddress =~
                            '''(?i)^f[cd][0-9a-f]{2}:''',

                    then="PRIVATE_INTERNAL",

                    else=if(
                        condition=
                            RemoteAddress =~
                                '''(?i)^(::ffff:)?169[.]254[.]'''
                            OR RemoteAddress =~
                                '''(?i)^fe[89ab][0-9a-f]:''',

                        then="LINK_LOCAL",

                        else=if(
                            condition=
                                RemoteAddress =~
                                    '''(?i)^(::ffff:)?(22[4-9]|23[0-9])[.]'''
                                OR RemoteAddress =~ '''(?i)^ff''',

                            then="MULTICAST",

                            else=if(
                                condition=
                                    RemoteAddress = "0.0.0.0"
                                    OR RemoteAddress = "::"
                                    OR RemoteAddress = "::ffff:0.0.0.0",

                                then="UNSPECIFIED",
                                else="PUBLIC_EXTERNAL"
                            )
                        )
                    )
                )
            )
        ) AS DestinationScope,

        Pid,
        ProcessName,
        ProcessPath,
        Username,
        CommandLine,

        if(
            condition=Pid > 0 OR ProcessName,
            then="ATTRIBUTED",
            else="UNATTRIBUTED"
        ) AS ProcessAttribution,

        format(
            format="%v|TCP|%v|%v|%v|%v|%v",
            args=[
                ClientId,
                LocalAddress,
                LocalPort,
                RemoteAddress,
                RemotePort,
                Pid
            ]
        ) AS ConnectionKey

    FROM EstablishedRaw


-- ------------------------------------------------------------
-- 3. Remove exact duplicate connection records
-- ------------------------------------------------------------

LET EstablishedDeduplicated <=
    SELECT
        ClientId,
        Fqdn,
        Transport,
        AddressFamily,
        ConnectionState,
        LocalAddress,
        LocalPort,
        RemoteAddress,
        RemotePort,
        DestinationScope,
        Pid,
        ProcessName,
        ProcessPath,
        Username,
        CommandLine,
        ProcessAttribution,
        ConnectionKey

    FROM EstablishedNormalized

    GROUP BY ConnectionKey


-- ------------------------------------------------------------
-- 4. Final inventory
-- ------------------------------------------------------------

SELECT
    ClientId,
    Fqdn,
    Transport,
    AddressFamily,
    ConnectionState,
    LocalAddress,
    LocalPort,
    RemoteAddress,
    RemotePort,
    DestinationScope,
    Pid,
    ProcessName,
    ProcessPath,
    Username,
    CommandLine,
    ProcessAttribution,
    ConnectionKey

FROM EstablishedDeduplicated

ORDER BY
    ClientId
```

## Cell 8 (markdown)

# Established Connection Summary per Client

Deduplicated baseline summary of established TCP connections per client, separated by destination scope and process attribution, with unique remote IP, destination port, and communicating process counts. This cell does not generate findings or contribute to the Master Risk Score.

## Cell 9 (vql)

```vql
-- ============================================================
-- Established Connection Summary per Client
-- Role: Baseline / Connection Summary
-- Risk Score Eligible: No
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- Helper: Convert a list into a unique-value set
-- ------------------------------------------------------------

LET SET(LIST) = to_dict(item={
    SELECT
        _value AS _key,
        TRUE AS _value

    FROM foreach(row=LIST)

    WHERE _value
})


-- ------------------------------------------------------------
-- 1. Normalize established connections
-- ------------------------------------------------------------

LET EstablishedNormalized <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Laddr AS LocalAddress,
        Lport AS LocalPort,

        Raddr AS RemoteAddress,
        Rport AS RemotePort,

        Pid,
        ProcInfo.Name AS ProcessName,
        ProcInfo.Exe AS ProcessPath,

        if(
            condition=NOT Raddr OR Raddr = "",
            then="UNKNOWN",

            else=if(
                condition=
                    Raddr =~ '''(?i)^(::ffff:)?127[.]'''
                    OR Raddr = "::1",

                then="LOOPBACK",

                else=if(
                    condition=
                        Raddr =~ '''(?i)^(::ffff:)?10[.]'''
                        OR Raddr =~
                            '''(?i)^(::ffff:)?172[.](1[6-9]|2[0-9]|3[01])[.]'''
                        OR Raddr =~
                            '''(?i)^(::ffff:)?192[.]168[.]'''
                        OR Raddr =~
                            '''(?i)^f[cd][0-9a-f]{2}:''',

                    then="PRIVATE_INTERNAL",

                    else=if(
                        condition=
                            Raddr =~
                                '''(?i)^(::ffff:)?169[.]254[.]'''
                            OR Raddr =~
                                '''(?i)^fe[89ab][0-9a-f]:''',

                        then="LINK_LOCAL",

                        else=if(
                            condition=
                                Raddr =~
                                    '''(?i)^(::ffff:)?(22[4-9]|23[0-9])[.]'''
                                OR Raddr =~ '''(?i)^ff''',

                            then="MULTICAST",

                            else=if(
                                condition=
                                    Raddr = "0.0.0.0"
                                    OR Raddr = "::"
                                    OR Raddr = "::ffff:0.0.0.0",

                                then="UNSPECIFIED",
                                else="PUBLIC_EXTERNAL"
                            )
                        )
                    )
                )
            )
        ) AS DestinationScope,

        if(
            condition=Pid > 0 OR ProcInfo.Name,
            then=format(
                format="%v|%v|%v",
                args=[
                    Pid,
                    ProcInfo.Name,
                    ProcInfo.Exe
                ]
            ),
            else=""
        ) AS ProcessEntity,

        if(
            condition=Rport > 0,
            then=format(
                format="%v",
                args=[Rport]
            ),
            else=""
        ) AS DestinationPortEntity,

        format(
            format="%v|TCP|%v|%v|%v|%v|%v",
            args=[
                ClientId,
                Laddr,
                Lport,
                Raddr,
                Rport,
                Pid
            ]
        ) AS ConnectionKey

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ '''(?i)^(ESTAB|ESTABLISHED)$'''


-- ------------------------------------------------------------
-- 2. Remove duplicate connection records
-- ------------------------------------------------------------

LET EstablishedDeduplicated <=
    SELECT
        ClientId,
        Fqdn,
        LocalAddress,
        LocalPort,
        RemoteAddress,
        RemotePort,
        DestinationScope,
        Pid,
        ProcessName,
        ProcessPath,
        ProcessEntity,
        DestinationPortEntity,
        ConnectionKey

    FROM EstablishedNormalized

    GROUP BY ConnectionKey


-- ------------------------------------------------------------
-- 3. Aggregate connection metrics per client
-- ------------------------------------------------------------

LET ConnectionSummary <=
    SELECT
        ClientId,
        Fqdn,

        count() AS EstablishedConnectionCount,

        sum(
            item=if(
                condition=DestinationScope = "PRIVATE_INTERNAL",
                then=1,
                else=0
            )
        ) AS InternalConnectionCount,

        sum(
            item=if(
                condition=DestinationScope = "PUBLIC_EXTERNAL",
                then=1,
                else=0
            )
        ) AS ExternalConnectionCount,

        sum(
            item=if(
                condition=DestinationScope = "LOOPBACK",
                then=1,
                else=0
            )
        ) AS LoopbackConnectionCount,

        sum(
            item=if(
                condition=
                    DestinationScope != "PRIVATE_INTERNAL"
                    AND DestinationScope != "PUBLIC_EXTERNAL"
                    AND DestinationScope != "LOOPBACK",

                then=1,
                else=0
            )
        ) AS OtherScopeConnectionCount,

        sum(
            item=if(
                condition=NOT Pid OR Pid <= 0,
                then=1,
                else=0
            )
        ) AS ConnectionWithoutPIDCount,

        enumerate(
            items=RemoteAddress
        ) AS RemoteAddressList,

        enumerate(
            items=DestinationPortEntity
        ) AS DestinationPortList,

        enumerate(
            items=ProcessEntity
        ) AS ProcessEntityList

    FROM EstablishedDeduplicated

    GROUP BY
        ClientId,
        Fqdn


-- ------------------------------------------------------------
-- 4. Final baseline summary
-- ------------------------------------------------------------

SELECT
    ClientId,
    Fqdn,

    EstablishedConnectionCount,
    InternalConnectionCount,
    ExternalConnectionCount,
    LoopbackConnectionCount,
    OtherScopeConnectionCount,
    ConnectionWithoutPIDCount,

    len(
        list=SET(LIST=RemoteAddressList)
    ) AS UniqueRemoteIPCount,

    len(
        list=SET(LIST=DestinationPortList)
    ) AS UniqueDestinationPortCount,

    len(
        list=SET(LIST=ProcessEntityList)
    ) AS UniqueCommunicatingProcessCount,

    if(
        condition=
            EstablishedConnectionCount =
                InternalConnectionCount +
                ExternalConnectionCount +
                LoopbackConnectionCount +
                OtherScopeConnectionCount,

        then="PASS",
        else="CHECK"
    ) AS CountValidation,

    FALSE AS RiskScoreEligible

FROM ConnectionSummary

ORDER BY
    ExternalConnectionCount DESC
```

## Cell 10 (markdown)

# Connections by Process

Deduplicated process-oriented summary of listening sockets and established TCP connections, including listener exposure, destination scope, process attribution, and unique network entities. This cell provides behavioral context only and does not generate findings or contribute to the Master Risk Score.

## Cell 11 (vql)

```vql
-- ============================================================
-- Connections by Process
-- Role: Process-Oriented Network Baseline
-- Risk Score Eligible: No
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- Helper: Convert a list into a unique-value set
-- ------------------------------------------------------------

LET SET(LIST) = to_dict(item={
    SELECT
        _value AS _key,
        TRUE AS _value

    FROM foreach(row=LIST)

    WHERE _value
})


-- ------------------------------------------------------------
-- 1. Collect listening and established socket records
-- ------------------------------------------------------------

LET NetworkRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Status,

        Laddr AS LocalAddress,
        Lport AS LocalPort,

        Raddr AS RemoteAddress,
        Rport AS RemotePort,

        Pid,
        ProcInfo.Name AS ProcessName,
        ProcInfo.Exe AS ProcessPath,
        ProcInfo.Username AS Username

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ '''(?i)^(LISTEN|ESTAB|ESTABLISHED)$'''


-- ------------------------------------------------------------
-- 2. Normalize socket, process, and destination context
-- ------------------------------------------------------------

LET NetworkNormalized <=
    SELECT
        ClientId,
        Fqdn,

        if(
            condition=Status =~ '''(?i)^LISTEN$''',
            then="LISTEN",
            else="ESTABLISHED"
        ) AS ConnectionState,

        LocalAddress,
        LocalPort,
        RemoteAddress,
        RemotePort,

        if(
            condition=Status =~ '''(?i)^LISTEN$''',

            then=if(
                condition=NOT LocalAddress OR LocalAddress = "",
                then="UNKNOWN_BINDING",

                else=if(
                    condition=
                        LocalAddress =~ '''^127[.]'''
                        OR LocalAddress = "::1",

                    then="LOOPBACK_ONLY",

                    else=if(
                        condition=
                            LocalAddress = "0.0.0.0"
                            OR LocalAddress = "::",

                        then="ALL_INTERFACES",
                        else="SPECIFIC_INTERFACE"
                    )
                )
            ),

            else="NOT_APPLICABLE"
        ) AS BindingScope,

        if(
            condition=Status =~ '''(?i)^LISTEN$''',
            then="NOT_APPLICABLE",

            else=if(
                condition=NOT RemoteAddress OR RemoteAddress = "",
                then="UNKNOWN",

                else=if(
                    condition=
                        RemoteAddress =~ '''(?i)^(::ffff:)?127[.]'''
                        OR RemoteAddress = "::1",

                    then="LOOPBACK",

                    else=if(
                        condition=
                            RemoteAddress =~ '''(?i)^(::ffff:)?10[.]'''
                            OR RemoteAddress =~
                                '''(?i)^(::ffff:)?172[.](1[6-9]|2[0-9]|3[01])[.]'''
                            OR RemoteAddress =~
                                '''(?i)^(::ffff:)?192[.]168[.]'''
                            OR RemoteAddress =~
                                '''(?i)^f[cd][0-9a-f]{2}:''',

                        then="PRIVATE_INTERNAL",

                        else=if(
                            condition=
                                RemoteAddress =~
                                    '''(?i)^(::ffff:)?169[.]254[.]'''
                                OR RemoteAddress =~
                                    '''(?i)^fe[89ab][0-9a-f]:''',

                            then="LINK_LOCAL",

                            else=if(
                                condition=
                                    RemoteAddress =~
                                        '''(?i)^(::ffff:)?(22[4-9]|23[0-9])[.]'''
                                    OR RemoteAddress =~ '''(?i)^ff''',

                                then="MULTICAST",

                                else=if(
                                    condition=
                                        RemoteAddress = "0.0.0.0"
                                        OR RemoteAddress = "::"
                                        OR RemoteAddress = "::ffff:0.0.0.0",

                                    then="UNSPECIFIED",
                                    else="PUBLIC_EXTERNAL"
                                )
                            )
                        )
                    )
                )
            )
        ) AS DestinationScope,

        Pid,
        ProcessName,
        ProcessPath,
        Username,

        if(
            condition=ProcessName OR ProcessPath,
            then="PROCESS_IDENTIFIED",

            else=if(
                condition=Pid > 0,
                then="PID_ONLY",
                else="UNATTRIBUTED"
            )
        ) AS ProcessAttribution,

        if(
            condition=ProcessName OR ProcessPath,

            then=format(
                format="%v|%v|%v|%v",
                args=[
                    ClientId,
                    ProcessName,
                    ProcessPath,
                    Username
                ]
            ),

            else=format(
                format="%v|UNATTRIBUTED|%v",
                args=[
                    ClientId,
                    Pid
                ]
            )
        ) AS ProcessEntityKey,

        if(
            condition=Pid > 0,
            then=format(
                format="%v",
                args=[Pid]
            ),
            else=""
        ) AS PidEntity,

        if(
            condition=
                Status =~ '''(?i)^(ESTAB|ESTABLISHED)$'''
                AND RemoteAddress,

            then=RemoteAddress,
            else=""
        ) AS RemoteAddressEntity,

        if(
            condition=
                Status =~ '''(?i)^(ESTAB|ESTABLISHED)$'''
                AND RemotePort > 0,

            then=format(
                format="%v",
                args=[RemotePort]
            ),
            else=""
        ) AS RemotePortEntity,

        if(
            condition=Status =~ '''(?i)^LISTEN$''',

            then=format(
                format="%v|LISTEN|%v|%v|%v",
                args=[
                    ClientId,
                    LocalAddress,
                    LocalPort,
                    Pid
                ]
            ),

            else=format(
                format="%v|ESTABLISHED|%v|%v|%v|%v|%v",
                args=[
                    ClientId,
                    LocalAddress,
                    LocalPort,
                    RemoteAddress,
                    RemotePort,
                    Pid
                ]
            )
        ) AS SocketKey

    FROM NetworkRaw


-- ------------------------------------------------------------
-- 3. Remove duplicate socket records
-- ------------------------------------------------------------

LET NetworkDeduplicated <=
    SELECT
        ClientId,
        Fqdn,
        ConnectionState,

        LocalAddress,
        LocalPort,
        RemoteAddress,
        RemotePort,

        BindingScope,
        DestinationScope,

        Pid,
        ProcessName,
        ProcessPath,
        Username,
        ProcessAttribution,
        ProcessEntityKey,

        PidEntity,
        RemoteAddressEntity,
        RemotePortEntity,
        SocketKey

    FROM NetworkNormalized

    GROUP BY SocketKey


-- ------------------------------------------------------------
-- 4. Aggregate network activity by process entity
-- ------------------------------------------------------------

LET ProcessSummary <=
    SELECT
        ClientId,
        Fqdn,

        ProcessName,
        ProcessPath,
        Username,
        ProcessAttribution,
        ProcessEntityKey,

        count() AS TotalSocketCount,

        sum(
            item=if(
                condition=ConnectionState = "LISTEN",
                then=1,
                else=0
            )
        ) AS ListeningSocketCount,

        sum(
            item=if(
                condition=ConnectionState = "ESTABLISHED",
                then=1,
                else=0
            )
        ) AS EstablishedConnectionCount,

        sum(
            item=if(
                condition=
                    ConnectionState = "LISTEN"
                    AND BindingScope = "LOOPBACK_ONLY",

                then=1,
                else=0
            )
        ) AS LoopbackListenerCount,

        sum(
            item=if(
                condition=
                    ConnectionState = "LISTEN"
                    AND (
                        BindingScope = "ALL_INTERFACES"
                        OR BindingScope = "SPECIFIC_INTERFACE"
                    ),

                then=1,
                else=0
            )
        ) AS PotentiallyExposedListenerCount,

        sum(
            item=if(
                condition=
                    ConnectionState = "LISTEN"
                    AND BindingScope = "UNKNOWN_BINDING",

                then=1,
                else=0
            )
        ) AS UnknownBindingListenerCount,

        sum(
            item=if(
                condition=
                    ConnectionState = "ESTABLISHED"
                    AND DestinationScope = "PRIVATE_INTERNAL",

                then=1,
                else=0
            )
        ) AS InternalConnectionCount,

        sum(
            item=if(
                condition=
                    ConnectionState = "ESTABLISHED"
                    AND DestinationScope = "PUBLIC_EXTERNAL",

                then=1,
                else=0
            )
        ) AS ExternalConnectionCount,

        sum(
            item=if(
                condition=
                    ConnectionState = "ESTABLISHED"
                    AND DestinationScope = "LOOPBACK",

                then=1,
                else=0
            )
        ) AS LoopbackConnectionCount,

        sum(
            item=if(
                condition=
                    ConnectionState = "ESTABLISHED"
                    AND DestinationScope != "PRIVATE_INTERNAL"
                    AND DestinationScope != "PUBLIC_EXTERNAL"
                    AND DestinationScope != "LOOPBACK",

                then=1,
                else=0
            )
        ) AS OtherScopeConnectionCount,

        enumerate(items=PidEntity) AS PidList,
        enumerate(items=RemoteAddressEntity) AS RemoteAddressList,
        enumerate(items=RemotePortEntity) AS RemotePortList

    FROM NetworkDeduplicated

    GROUP BY ProcessEntityKey


-- ------------------------------------------------------------
-- 5. Final process-oriented baseline
-- ------------------------------------------------------------

SELECT
    ClientId,
    Fqdn,

    ProcessName,
    ProcessPath,
    Username,
    ProcessAttribution,

    if(
        condition=
            ListeningSocketCount > 0
            AND EstablishedConnectionCount > 0,

        then="LISTENER_AND_CONNECTION",

        else=if(
            condition=ListeningSocketCount > 0,
            then="LISTENER_ONLY",
            else="CONNECTION_ONLY"
        )
    ) AS NetworkActivityType,

    TotalSocketCount,
    ListeningSocketCount,
    EstablishedConnectionCount,

    LoopbackListenerCount,
    PotentiallyExposedListenerCount,
    UnknownBindingListenerCount,

    InternalConnectionCount,
    ExternalConnectionCount,
    LoopbackConnectionCount,
    OtherScopeConnectionCount,

    len(
        list=SET(LIST=PidList)
    ) AS UniquePIDCount,

    len(
        list=SET(LIST=RemoteAddressList)
    ) AS UniqueRemoteIPCount,

    len(
        list=SET(LIST=RemotePortList)
    ) AS UniqueDestinationPortCount,

    if(
        condition=
            TotalSocketCount =
                ListeningSocketCount +
                EstablishedConnectionCount

            AND

            ListeningSocketCount =
                LoopbackListenerCount +
                PotentiallyExposedListenerCount +
                UnknownBindingListenerCount

            AND

            EstablishedConnectionCount =
                InternalConnectionCount +
                ExternalConnectionCount +
                LoopbackConnectionCount +
                OtherScopeConnectionCount,

        then="PASS",
        else="CHECK"
    ) AS CountValidation,

    ProcessEntityKey,

    FALSE AS RiskScoreEligible

FROM ProcessSummary

ORDER BY
    PotentiallyExposedListenerCount DESC
```

## Cell 12 (markdown)

# Routing Table Review

Normalized and deduplicated review of Linux routes collected from the main IPv4 routing table, including destination, gateway, interface, route origin, scope, metric, and collection health. Review labels provide investigation context only and do not generate findings or contribute to the Master Risk Score.

## Cell 13 (vql)

```vql
-- ============================================================
-- Routing Table Review
-- Role: Network Baseline / Investigation Context
-- Coverage: Main IPv4 routing table snapshot
-- Risk Score Eligible: No
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- 1. Read raw command results
-- ------------------------------------------------------------

LET RouteCommands <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Command,
        Stdout,
        Stderr,
        ReturnCode

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/RoutingTable"
    )


-- ------------------------------------------------------------
-- 2. Split multiline stdout into individual route records
-- ------------------------------------------------------------

LET RouteLines <=
    SELECT
        ClientId,
        Fqdn,
        Command,
        ReturnCode,
        Stderr,
        _value AS RawRoute

    FROM foreach(
        row=RouteCommands,

        query={
            SELECT
                ClientId,
                Fqdn,
                Command,
                ReturnCode,
                Stderr,
                _value

            FROM foreach(
                row=split(
                    string=Stdout,
                    sep='''\r?\n'''
                )
            )

            WHERE _value =~ '''\S'''
        }
    )

    WHERE ReturnCode = 0


-- ------------------------------------------------------------
-- 3. Extract route fields from each line
-- ------------------------------------------------------------

LET RouteParsed <=
    SELECT
        ClientId,
        Fqdn,
        Command,
        ReturnCode,
        Stderr,
        RawRoute,

        parse_string_with_regex(
            string=RawRoute,

            regex=[
                '''^(?P<Destination>\S+)''',

                '''^(?P<RouteType>blackhole|unreachable|prohibit|throw|nat|local|broadcast|multicast|anycast)\s+(?P<Destination>\S+)''',

                '''(?:^|\s)via\s+(?P<Gateway>\S+)''',
                '''(?:^|\s)dev\s+(?P<Interface>\S+)''',
                '''(?:^|\s)proto\s+(?P<RouteProtocol>\S+)''',
                '''(?:^|\s)scope\s+(?P<RouteScope>\S+)''',
                '''(?:^|\s)src\s+(?P<PreferredSource>\S+)''',
                '''(?:^|\s)metric\s+(?P<Metric>\d+)''',
                '''(?:^|\s)table\s+(?P<RoutingTable>\S+)'''
            ]
        ) AS Parsed

    FROM RouteLines


-- ------------------------------------------------------------
-- 4. Normalize extracted fields
-- ------------------------------------------------------------

LET RouteExtracted <=
    SELECT
        ClientId,
        Fqdn,
        Command,
        ReturnCode,
        Stderr,
        RawRoute,

        Parsed.Destination AS Destination,

        if(
            condition=Parsed.RouteType,
            then=lowcase(string=Parsed.RouteType),
            else="unicast"
        ) AS RouteType,

        Parsed.Gateway AS Gateway,
        Parsed.Interface AS Interface,

        if(
            condition=Parsed.RouteProtocol,
            then=lowcase(string=Parsed.RouteProtocol),
            else=""
        ) AS RouteProtocol,

        if(
            condition=Parsed.RouteScope,
            then=lowcase(string=Parsed.RouteScope),
            else=""
        ) AS RouteScope,

        Parsed.PreferredSource AS PreferredSource,
        Parsed.Metric AS Metric,

        if(
            condition=Parsed.RoutingTable,
            then=Parsed.RoutingTable,
            else="main"
        ) AS RoutingTable

    FROM RouteParsed


-- ------------------------------------------------------------
-- 5. Add routing context
-- ------------------------------------------------------------

LET RouteClassified <=
    SELECT
        ClientId,
        Fqdn,

        "ROUTE" AS RecordType,
        "MAIN_IPV4_TABLE_SNAPSHOT" AS CoverageScope,

        if(
            condition=Stderr =~ '''\S''',
            then="SUCCESS_WITH_STDERR",
            else="SUCCESS"
        ) AS CollectionStatus,

        Destination,
        RouteType,
        Gateway,
        Interface,
        RouteProtocol,
        RouteScope,
        PreferredSource,
        Metric,
        RoutingTable,

        if(
            condition=Destination =~ ":"
                      OR Gateway =~ ":",

            then="IPv6",
            else="IPv4"
        ) AS AddressFamily,

        if(
            condition=Destination = "default",
            then="DEFAULT_ROUTE",

            else=if(
                condition=RouteType != "unicast",
                then="NON_UNICAST_ROUTE",

                else=if(
                    condition=Gateway,
                    then="GATEWAY_ROUTE",

                    else=if(
                        condition=
                            RouteScope = "link"
                            OR RouteProtocol = "kernel",

                        then="DIRECTLY_CONNECTED",
                        else="OTHER_ROUTE"
                    )
                )
            )
        ) AS RouteClass,

        if(
            condition=Destination = "default",
            then="DEFAULT",

            else=if(
                condition=
                    Destination =~ '''^169[.]254[.]'''
                    OR Destination =~ '''(?i)^fe[89ab][0-9a-f]:''',

                then="LINK_LOCAL",

                else=if(
                    condition=
                        Destination =~ '''^127[.]'''
                        OR Destination =~ '''^::1''',

                    then="LOOPBACK",

                    else=if(
                        condition=
                            Destination =~ '''^10[.]'''
                            OR Destination =~
                                '''^172[.](1[6-9]|2[0-9]|3[01])[.]'''
                            OR Destination =~ '''^192[.]168[.]'''
                            OR Destination =~ '''(?i)^f[cd][0-9a-f]{2}:''',

                        then="PRIVATE_INTERNAL",

                        else=if(
                            condition=
                                Destination =~
                                    '''^(22[4-9]|23[0-9])[.]'''
                                OR Destination =~ '''(?i)^ff''',

                            then="MULTICAST",
                            else="PUBLIC_OR_OTHER"
                        )
                    )
                )
            )
        ) AS DestinationScope,

        if(
            condition=NOT Gateway,
            then="DIRECT_ROUTE",

            else=if(
                condition=
                    Gateway =~ '''^10[.]'''
                    OR Gateway =~
                        '''^172[.](1[6-9]|2[0-9]|3[01])[.]'''
                    OR Gateway =~ '''^192[.]168[.]'''
                    OR Gateway =~ '''(?i)^f[cd][0-9a-f]{2}:''',

                then="PRIVATE_INTERNAL_GATEWAY",

                else=if(
                    condition=
                        Gateway =~ '''^169[.]254[.]'''
                        OR Gateway =~ '''(?i)^fe[89ab][0-9a-f]:''',

                    then="LINK_LOCAL_GATEWAY",
                    else="PUBLIC_OR_OTHER_GATEWAY"
                )
            )
        ) AS GatewayScope,

        if(
            condition=RouteProtocol = "dhcp",
            then="DHCP",

            else=if(
                condition=RouteProtocol = "kernel",
                then="KERNEL_CONNECTED",

                else=if(
                    condition=RouteProtocol = "static",
                    then="STATIC",

                    else=if(
                        condition=RouteProtocol = "ra",
                        then="ROUTER_ADVERTISEMENT",

                        else=if(
                            condition=RouteProtocol,
                            then=upcase(string=RouteProtocol),
                            else="UNSPECIFIED"
                        )
                    )
                )
            )
        ) AS RouteOrigin,

        if(
            condition=RawRoute =~ '''(?i)\bnexthop\b''',
            then="PARTIAL_MULTIPATH_PARSE",
            else="STANDARD_PARSE"
        ) AS ParseConfidence,

        RawRoute,
        Stderr,
        ReturnCode,
        Command

    FROM RouteExtracted


-- ------------------------------------------------------------
-- 6. Add review labels and exact deduplication key
-- ------------------------------------------------------------

LET NormalizedRoutes <=
    SELECT
        ClientId,
        Fqdn,
        RecordType,
        CoverageScope,
        CollectionStatus,

        AddressFamily,
        RoutingTable,
        RouteClass,
        RouteType,

        Destination,
        DestinationScope,

        Gateway,
        GatewayScope,

        Interface,
        RouteOrigin,
        RouteProtocol,
        RouteScope,
        PreferredSource,
        Metric,

        if(
            condition=RouteType != "unicast",
            then="NON_UNICAST_ROUTE_REVIEW",

            else=if(
                condition=Destination = "default",
                then="COMPARE_WITH_EXPECTED_DEFAULT_GATEWAY",

                else=if(
                    condition=
                        Gateway
                        AND (
                            RouteOrigin = "STATIC"
                            OR RouteOrigin = "UNSPECIFIED"
                        ),

                    then="STATIC_OR_UNSPECIFIED_GATEWAY_REVIEW",
                    else="BASELINE_CONTEXT"
                )
            )
        ) AS ReviewContext,

        ParseConfidence,
        RawRoute,
        Stderr,
        ReturnCode,
        Command,

        format(
            format="%v|%v",
            args=[
                ClientId,
                RawRoute
            ]
        ) AS RouteKey,

        FALSE AS RiskScoreEligible

    FROM RouteClassified


LET DeduplicatedRoutes <=
    SELECT *

    FROM NormalizedRoutes

    GROUP BY RouteKey


-- ------------------------------------------------------------
-- 7. Keep failed or empty collections visible
-- ------------------------------------------------------------

LET CollectionIssues <=
    SELECT
        ClientId,
        Fqdn,

        "COLLECTION_STATUS" AS RecordType,
        "MAIN_IPV4_TABLE_SNAPSHOT" AS CoverageScope,

        if(
            condition=ReturnCode != 0,
            then="COMMAND_FAILED",
            else="NO_ROUTE_OUTPUT_REVIEW"
        ) AS CollectionStatus,

        "" AS AddressFamily,
        "" AS RoutingTable,
        "" AS RouteClass,
        "" AS RouteType,
        "" AS Destination,
        "" AS DestinationScope,
        "" AS Gateway,
        "" AS GatewayScope,
        "" AS Interface,
        "" AS RouteOrigin,
        "" AS RouteProtocol,
        "" AS RouteScope,
        "" AS PreferredSource,
        "" AS Metric,

        "COLLECTION_REVIEW_REQUIRED" AS ReviewContext,
        "NOT_APPLICABLE" AS ParseConfidence,

        Stdout AS RawRoute,
        Stderr,
        ReturnCode,
        Command,

        format(
            format="%v|COLLECTION_STATUS",
            args=[ClientId]
        ) AS RouteKey,

        FALSE AS RiskScoreEligible

    FROM RouteCommands

    WHERE ReturnCode != 0
      OR NOT Stdout
      OR Stdout =~ '''^\s*$'''


-- ------------------------------------------------------------
-- 8. Final output
-- ------------------------------------------------------------

SELECT *

FROM chain(
    a=DeduplicatedRoutes,
    b=CollectionIssues
)

ORDER BY
    ClientId
```

## Cell 14 (markdown)

# DNS Configuration Review

Normalized and deduplicated review of Linux hosts mappings, resolver directives, systemd-resolved settings, and active resolver context. Review labels identify configuration that should be compared with the approved network baseline; they do not independently generate findings or contribute to the Master Risk Score.

## Cell 15 (vql)

```vql
-- ============================================================
-- DNS Configuration Review
-- Role: DNS and Name-Resolution Baseline
-- Finding Generated: No
-- Risk Score Eligible: No
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- 1. Read collected DNS configuration lines
-- ------------------------------------------------------------

LET DNSRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Path,
        Line AS RawLine,

        Severity AS SourceSeverity,
        Reason AS SourceReason

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/DNSConfigReview"
    )

    WHERE Line
      AND Line =~ '''\S'''


-- ------------------------------------------------------------
-- 2. Parse supported configuration formats
-- ------------------------------------------------------------

LET DNSParsed <=
    SELECT
        ClientId,
        Fqdn,
        Path,
        RawLine,
        SourceSeverity,
        SourceReason,

        parse_string_with_regex(
            string=RawLine,

            regex=[
                -- /etc/resolv.conf directives
                '''^\s*(?P<ResolverDirective>nameserver|search|domain|options|sortlist)\s+(?P<ResolverValue>[^#]+?)\s*(?:#.*)?$''',

                -- systemd-resolved configuration
                '''^\s*(?P<SystemdKey>DNS|FallbackDNS|Domains|LLMNR|MulticastDNS|DNSSEC|DNSOverTLS|Cache|DNSStubListener)\s*=\s*(?P<SystemdValue>[^#]*?)\s*(?:#.*)?$''',

                -- resolvectl status-style output
                '''^\s*(?P<ResolvedLabel>Current DNS Server|DNS Servers|DNS Domain|Protocols)\s*:\s*(?P<ResolvedValue>.+?)\s*$''',

                -- /etc/hosts mapping
                '''^\s*(?P<HostAddress>\S+)\s+(?P<Hostnames>[^#]+?)\s*(?:#.*)?$'''
            ]
        ) AS Parsed

    FROM DNSRaw


-- ------------------------------------------------------------
-- 3. Normalize source and record type
-- ------------------------------------------------------------

LET DNSNormalized <=
    SELECT
        ClientId,
        Fqdn,
        Path,

        if(
            condition=Path =~ '''(?i)/hosts$''',
            then="HOSTS_FILE",

            else=if(
                condition=Path =~ '''(?i)resolv[.]conf$''',
                then="RESOLVER_CONFIGURATION",

                else=if(
                    condition=Path =~ '''(?i)resolved[.]conf''',
                    then="SYSTEMD_RESOLVED_CONFIGURATION",

                    else=if(
                        condition=Parsed.ResolvedLabel,
                        then="ACTIVE_RESOLVER_STATUS",
                        else="OTHER_DNS_CONFIGURATION"
                    )
                )
            )
        ) AS SourceType,

        if(
            condition=Path =~ '''(?i)/hosts$''',
            then="HOSTS_MAPPING",

            else=if(
                condition=Parsed.ResolverDirective =~
                    '''(?i)^nameserver$''',

                then="NAMESERVER",

                else=if(
                    condition=Parsed.ResolverDirective =~
                        '''(?i)^(search|domain)$''',

                    then="SEARCH_DOMAIN",

                    else=if(
                        condition=Parsed.ResolverDirective =~
                            '''(?i)^(options|sortlist)$''',

                        then="RESOLVER_OPTION",

                        else=if(
                            condition=Parsed.SystemdKey,
                            then="SYSTEMD_RESOLVED_SETTING",

                            else=if(
                                condition=Parsed.ResolvedLabel,
                                then="RESOLVER_STATUS",
                                else="UNPARSED_CONFIGURATION"
                            )
                        )
                    )
                )
            )
        ) AS RecordType,

        if(
            condition=Path =~ '''(?i)/hosts$''',
            then="HOST_ADDRESS",

            else=if(
                condition=Parsed.ResolverDirective,
                then=Parsed.ResolverDirective,

                else=if(
                    condition=Parsed.SystemdKey,
                    then=Parsed.SystemdKey,

                    else=if(
                        condition=Parsed.ResolvedLabel,
                        then=Parsed.ResolvedLabel,
                        else="UNPARSED"
                    )
                )
            )
        ) AS ConfigurationKey,

        if(
            condition=Path =~ '''(?i)/hosts$''',
            then=Parsed.Hostnames,

            else=if(
                condition=Parsed.ResolverDirective,
                then=Parsed.ResolverValue,

                else=if(
                    condition=Parsed.SystemdKey,
                    then=Parsed.SystemdValue,

                    else=if(
                        condition=Parsed.ResolvedLabel,
                        then=Parsed.ResolvedValue,
                        else=RawLine
                    )
                )
            )
        ) AS ConfigurationValue,

        if(
            condition=Path =~ '''(?i)/hosts$''',
            then=Parsed.HostAddress,

            else=if(
                condition=Parsed.ResolverDirective =~
                    '''(?i)^nameserver$''',

                then=Parsed.ResolverValue,

                else=if(
                    condition=Parsed.SystemdKey =~
                        '''(?i)^(DNS|FallbackDNS)$''',

                    then=Parsed.SystemdValue,

                    else=if(
                        condition=Parsed.ResolvedLabel =~
                            '''(?i)^(Current DNS Server|DNS Servers)$''',

                        then=Parsed.ResolvedValue,
                        else=""
                    )
                )
            )
        ) AS AddressValue,

        Parsed.HostAddress AS HostAddress,
        Parsed.Hostnames AS Hostnames,

        RawLine,
        SourceSeverity,
        SourceReason

    FROM DNSParsed


-- ------------------------------------------------------------
-- 4. Determine address family
-- ------------------------------------------------------------

LET DNSAddressFamily <=
    SELECT
        ClientId,
        Fqdn,
        Path,

        SourceType,
        RecordType,

        ConfigurationKey,
        ConfigurationValue,

        AddressValue,
        HostAddress,
        Hostnames,

        if(
            condition=NOT AddressValue,
            then="NOT_APPLICABLE",

            else=if(
                condition=AddressValue =~ '''\s''',
                then="MULTI_VALUE_OR_UNPARSED",

                else=if(
                    condition=AddressValue =~
                        '''^[0-9]{1,3}([.][0-9]{1,3}){3}$''',

                    then="IPv4",

                    else=if(
                        condition=AddressValue =~ ''':''',
                        then="IPv6",
                        else="UNKNOWN"
                    )
                )
            )
        ) AS AddressFamily,

        RawLine,
        SourceSeverity,
        SourceReason

    FROM DNSNormalized


-- ------------------------------------------------------------
-- 5. Classify address scope
-- ------------------------------------------------------------

LET DNSAddressContext <=
    SELECT
        ClientId,
        Fqdn,
        Path,

        SourceType,
        RecordType,

        ConfigurationKey,
        ConfigurationValue,

        AddressValue,
        AddressFamily,

        HostAddress,
        Hostnames,

        if(
            condition=NOT AddressValue,
            then="NOT_APPLICABLE",

            else=if(
                condition=AddressValue =~ '''\s''',
                then="MULTI_VALUE_OR_UNKNOWN",

                else=if(
                    condition=
                        AddressValue =~ '''(?i)^(::ffff:)?127[.]'''
                        OR AddressValue = "::1",

                    then="LOOPBACK",

                    else=if(
                        condition=
                            AddressValue =~ '''(?i)^(::ffff:)?10[.]'''
                            OR AddressValue =~
                                '''(?i)^(::ffff:)?172[.](1[6-9]|2[0-9]|3[01])[.]'''
                            OR AddressValue =~
                                '''(?i)^(::ffff:)?192[.]168[.]'''
                            OR AddressValue =~
                                '''(?i)^f[cd][0-9a-f]{2}:''',

                        then="PRIVATE_INTERNAL",

                        else=if(
                            condition=
                                AddressValue =~
                                    '''(?i)^(::ffff:)?169[.]254[.]'''
                                OR AddressValue =~
                                    '''(?i)^fe[89ab][0-9a-f]:''',

                            then="LINK_LOCAL",

                            else=if(
                                condition=
                                    AddressValue =~
                                        '''(?i)^(::ffff:)?(22[4-9]|23[0-9])[.]'''
                                    OR AddressValue =~ '''(?i)^ff''',

                                then="MULTICAST",

                                else=if(
                                    condition=
                                        AddressValue = "0.0.0.0"
                                        OR AddressValue = "::"
                                        OR AddressValue = "::ffff:0.0.0.0",

                                    then="UNSPECIFIED",

                                    else=if(
                                        condition=
                                            AddressFamily = "IPv4"
                                            OR AddressFamily = "IPv6",

                                        then="GLOBAL_OR_OTHER",
                                        else="INVALID_OR_NON_IP"
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS AddressScope,

        RawLine,
        SourceSeverity,
        SourceReason

    FROM DNSAddressFamily


-- ------------------------------------------------------------
-- 6. Add evidence-based review context
-- ------------------------------------------------------------

LET DNSReviewed <=
    SELECT
        ClientId,
        Fqdn,
        Path,

        SourceType,
        RecordType,

        ConfigurationKey,
        ConfigurationValue,

        AddressValue,
        AddressFamily,
        AddressScope,

        HostAddress,
        Hostnames,

        if(
            condition=
                RecordType = "HOSTS_MAPPING"
                AND HostAddress = "127.0.0.1"
                AND Hostnames =~
                    '''(?i)^localhost(\s|$)''',

            then="STANDARD_LOCALHOST_MAPPING",

            else=if(
                condition=
                    RecordType = "HOSTS_MAPPING"
                    AND HostAddress = "127.0.1.1",

                then="LOCAL_HOSTNAME_MAPPING_CONTEXT",

                else=if(
                    condition=
                        RecordType = "HOSTS_MAPPING"
                        AND HostAddress = "::1"
                        AND Hostnames =~
                            '''(?i)^(localhost|ip6-localhost|ip6-loopback)(\s|$)''',

                    then="STANDARD_IPV6_LOCALHOST_MAPPING",

                    else=if(
                        condition=
                            RecordType = "HOSTS_MAPPING"
                            AND HostAddress =~
                                '''(?i)^(fe00::0|ff00::0|ff02::1|ff02::2|ff02::3)$'''
                            AND Hostnames =~
                                '''(?i)^ip6-''',

                        then="STANDARD_IPV6_HOSTS_ENTRY",

                        else=if(
                            condition=
                                RecordType = "HOSTS_MAPPING"
                                AND AddressScope = "LOOPBACK",

                            then="LOOPBACK_REDIRECTION_REVIEW",

                            else=if(
                                condition=
                                    RecordType = "HOSTS_MAPPING"
                                    AND AddressScope = "UNSPECIFIED",

                                then="SINKHOLE_OR_BLOCKING_MAPPING_REVIEW",

                                else=if(
                                    condition=
                                        RecordType = "HOSTS_MAPPING",

                                    then="STATIC_HOSTS_MAPPING_COMPARE_WITH_BASELINE",

                                    else=if(
                                        condition=
                                            RecordType = "NAMESERVER"
                                            AND AddressValue = "127.0.0.53",

                                        then="SYSTEMD_RESOLVED_STUB",

                                        else=if(
                                            condition=
                                                RecordType = "NAMESERVER"
                                                AND AddressScope = "LOOPBACK",

                                            then="LOCAL_RESOLVER_CONTEXT",

                                            else=if(
                                                condition=
                                                    RecordType = "NAMESERVER"
                                                    AND AddressScope =
                                                        "PRIVATE_INTERNAL",

                                                then="INTERNAL_DNS_COMPARE_WITH_POLICY",

                                                else=if(
                                                    condition=
                                                        RecordType = "NAMESERVER"
                                                        AND AddressScope =
                                                            "GLOBAL_OR_OTHER",

                                                    then="EXTERNAL_DNS_COMPARE_WITH_POLICY",

                                                    else=if(
                                                        condition=
                                                            RecordType =
                                                                "NAMESERVER",

                                                        then="NAMESERVER_VALUE_REVIEW",

                                                        else=if(
                                                            condition=
                                                                RecordType =
                                                                    "SEARCH_DOMAIN",

                                                            then="SEARCH_DOMAIN_COMPARE_WITH_POLICY",

                                                            else=if(
                                                                condition=
                                                                    RecordType =
                                                                        "RESOLVER_OPTION",

                                                                then="RESOLVER_OPTION_CONTEXT",

                                                                else=if(
                                                                    condition=
                                                                        RecordType =
                                                                            "SYSTEMD_RESOLVED_SETTING"
                                                                        AND ConfigurationKey =~
                                                                            '''(?i)^(DNS|FallbackDNS)$''',

                                                                    then="SYSTEMD_DNS_COMPARE_WITH_POLICY",

                                                                    else=if(
                                                                        condition=
                                                                            RecordType =
                                                                                "SYSTEMD_RESOLVED_SETTING"
                                                                            AND ConfigurationKey =~
                                                                                '''(?i)^Domains$''',

                                                                        then="SEARCH_OR_ROUTE_DOMAIN_REVIEW",

                                                                        else=if(
                                                                            condition=
                                                                                RecordType =
                                                                                    "SYSTEMD_RESOLVED_SETTING",

                                                                            then="SYSTEMD_RESOLVED_OPTION_CONTEXT",

                                                                            else=if(
                                                                                condition=
                                                                                    RecordType =
                                                                                        "RESOLVER_STATUS",

                                                                                then="ACTIVE_RESOLVER_CONTEXT",
                                                                                else="UNPARSED_CONFIGURATION_REVIEW"
                                                                            )
                                                                        )
                                                                    )
                                                                )
                                                            )
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS ReviewContext,

        RawLine,
        SourceSeverity,
        SourceReason,

        format(
            format="%v|%v|%v",
            args=[
                ClientId,
                Path,
                RawLine
            ]
        ) AS RecordKey

    FROM DNSAddressContext


-- ------------------------------------------------------------
-- 7. Set review state without generating a finding
-- ------------------------------------------------------------

LET DNSFinal <=
    SELECT
        ClientId,
        Fqdn,
        Path,

        SourceType,
        RecordType,

        ConfigurationKey,
        ConfigurationValue,

        AddressValue,
        AddressFamily,
        AddressScope,

        HostAddress,
        Hostnames,

        ReviewContext,

        if(
            condition=ReviewContext =~
                '''(?i)(REVIEW|COMPARE)''',

            then=TRUE,
            else=FALSE
        ) AS ReviewRequired,

        SourceSeverity,
        SourceReason,
        RawLine,

        RecordKey,

        FALSE AS FindingGenerated,
        FALSE AS RiskScoreEligible

    FROM DNSReviewed


-- ------------------------------------------------------------
-- 8. Remove exact duplicate configuration records
-- ------------------------------------------------------------

LET DNSDeduplicated <=
    SELECT *

    FROM DNSFinal

    GROUP BY RecordKey


-- ------------------------------------------------------------
-- 9. Final output
-- ------------------------------------------------------------

SELECT
    ClientId,
    Fqdn,
    Path,

    SourceType,
    RecordType,

    ConfigurationKey,
    ConfigurationValue,

    AddressValue,
    AddressFamily,
    AddressScope,

    HostAddress,
    Hostnames,

    ReviewContext,
    ReviewRequired,

    SourceSeverity,
    SourceReason,
    RawLine,

    FindingGenerated,
    RiskScoreEligible

FROM DNSDeduplicated

ORDER BY
    ClientId
```

## Cell 16 (markdown)

# Firewall Rules Review

Normalized review of Linux local firewall configuration collected from iptables, nftables, and UFW. The analysis distinguishes successful empty collections, inactive firewall frontends, default chain policies, and explicit allow or deny rule evidence. Results provide security-posture context and do not independently indicate compromise or contribute to the Master Risk Score.

## Cell 17 (vql)

```vql
-- ============================================================
-- Firewall Rules Review
-- Role: Local Firewall Security-Posture Baseline
-- Telemetry Compatibility: Supporting
-- Finding Generated: No
-- Risk Score Eligible: No
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- 1. Read raw firewall collection results
-- ------------------------------------------------------------

LET FirewallRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Tool,
        Stdout,
        Stderr,
        ReturnCode,

        if(
            condition=Tool =~ '''(?i)^iptables-save$''',
            then="IPTABLES",

            else=if(
                condition=Tool =~ '''(?i)^nft\s+list\s+ruleset$''',
                then="NFTABLES",

                else=if(
                    condition=Tool =~ '''(?i)^ufw\s+status''',
                    then="UFW",
                    else="OTHER"
                )
            )
        ) AS FirewallBackend

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/FirewallRules"
    )


-- ------------------------------------------------------------
-- 2. Parse iptables filter policies and UFW status
-- ------------------------------------------------------------

LET FirewallParsed <=
    SELECT
        ClientId,
        Fqdn,
        Tool,
        FirewallBackend,
        Stdout,
        Stderr,
        ReturnCode,

        parse_string_with_regex(
            string=Stdout,

            regex=[
                -- Entire iptables filter-table block
                '''(?ms)^\*filter\s*(?P<FilterBlock>.*?)^COMMIT\s*$''',

                -- Built-in filter-chain policies
                '''(?ms)^\*filter\s+.*?^:INPUT\s+(?P<FilterInputPolicy>\S+)\s+\[''',
                '''(?ms)^\*filter\s+.*?^:FORWARD\s+(?P<FilterForwardPolicy>\S+)\s+\[''',
                '''(?ms)^\*filter\s+.*?^:OUTPUT\s+(?P<FilterOutputPolicy>\S+)\s+\[''',

                -- UFW status
                '''(?m)^\s*Status:\s*(?P<UFWStatus>\S+)\s*$''',
                '''(?m)^\s*Default:\s*(?P<UFWDefaultPolicies>.+?)\s*$''',
                '''(?m)^\s*Logging:\s*(?P<UFWLogging>.+?)\s*$'''
            ]
        ) AS Parsed

    FROM FirewallRaw


-- ------------------------------------------------------------
-- 3. Normalize fields and identify rule evidence
-- ------------------------------------------------------------

LET FirewallIndicators <=
    SELECT
        ClientId,
        Fqdn,
        Tool,
        FirewallBackend,

        if(
            condition=ReturnCode != 0,
            then="COMMAND_FAILED",

            else=if(
                condition=Stderr =~ '''\S''',
                then="SUCCESS_WITH_STDERR",
                else="SUCCESS"
            )
        ) AS CollectionStatus,

        if(
            condition=Parsed.FilterInputPolicy,
            then=upcase(string=Parsed.FilterInputPolicy),
            else=""
        ) AS FilterInputPolicy,

        if(
            condition=Parsed.FilterForwardPolicy,
            then=upcase(string=Parsed.FilterForwardPolicy),
            else=""
        ) AS FilterForwardPolicy,

        if(
            condition=Parsed.FilterOutputPolicy,
            then=upcase(string=Parsed.FilterOutputPolicy),
            else=""
        ) AS FilterOutputPolicy,

        if(
            condition=Parsed.FilterBlock,
            then=TRUE,
            else=FALSE
        ) AS FilterTablePresent,

        if(
            condition=Parsed.FilterBlock =~
                '''(?m)^\s*-A\s+\S+''',

            then=TRUE,
            else=FALSE
        ) AS ExplicitFilterRulesPresent,

        if(
            condition=Parsed.FilterBlock =~
                '''(?im)^\s*-A\s+.*(?:-j|--jump)\s+(DROP|REJECT)\b''',

            then=TRUE,
            else=FALSE
        ) AS DenyRuleEvidence,

        if(
            condition=Parsed.FilterBlock =~
                '''(?im)^\s*-A\s+.*(?:-j|--jump)\s+ACCEPT\b''',

            then=TRUE,
            else=FALSE
        ) AS AllowRuleEvidence,

        if(
            condition=
                FirewallBackend = "NFTABLES"
                AND Stdout
                AND Stdout =~ '''\S''',

            then=TRUE,
            else=FALSE
        ) AS NftRulesetPresent,

        if(
            condition=
                FirewallBackend = "NFTABLES"
                AND Stdout =~
                    '''(?i)(policy\s+(drop|reject)|\b(drop|reject)\b)''',

            then=TRUE,
            else=FALSE
        ) AS NftDenyEvidence,

        if(
            condition=Parsed.UFWStatus,
            then=lowcase(string=Parsed.UFWStatus),
            else=""
        ) AS UFWStatus,

        Parsed.UFWDefaultPolicies AS UFWDefaultPolicies,
        Parsed.UFWLogging AS UFWLogging,

        Parsed.FilterBlock AS IptablesFilterBlock,

        Stdout AS RawOutput,
        Stderr,
        ReturnCode

    FROM FirewallParsed


-- ------------------------------------------------------------
-- 4. Determine the state reported by each firewall tool
-- ------------------------------------------------------------

LET FirewallStates <=
    SELECT
        ClientId,
        Fqdn,
        Tool,
        FirewallBackend,
        CollectionStatus,

        FilterInputPolicy,
        FilterForwardPolicy,
        FilterOutputPolicy,

        FilterTablePresent,
        ExplicitFilterRulesPresent,
        DenyRuleEvidence,
        AllowRuleEvidence,

        NftRulesetPresent,
        NftDenyEvidence,

        UFWStatus,
        UFWDefaultPolicies,
        UFWLogging,

        if(
            condition=CollectionStatus = "COMMAND_FAILED",
            then="COMMAND_FAILED",

            else=if(
                condition=FirewallBackend = "IPTABLES",

                then=if(
                    condition=NOT FilterTablePresent,
                    then="FILTER_TABLE_NOT_RETURNED",

                    else=if(
                        condition=
                            FilterInputPolicy =~
                                '''(?i)^(DROP|REJECT)$''',

                        then="RESTRICTIVE_INPUT_DEFAULT_POLICY",

                        else=if(
                            condition=
                                FilterInputPolicy = "ACCEPT"
                                AND NOT ExplicitFilterRulesPresent,

                            then="DEFAULT_ACCEPT_NO_FILTER_RULES",

                            else=if(
                                condition=ExplicitFilterRulesPresent,
                                then="FILTER_RULESET_PRESENT",
                                else="FILTER_TABLE_REVIEW_REQUIRED"
                            )
                        )
                    )
                ),

                else=if(
                    condition=FirewallBackend = "NFTABLES",

                    then=if(
                        condition=NftRulesetPresent,
                        then="RULESET_PRESENT",
                        else="EMPTY_RULESET"
                    ),

                    else=if(
                        condition=FirewallBackend = "UFW",

                        then=if(
                            condition=UFWStatus = "active",
                            then="ACTIVE",

                            else=if(
                                condition=UFWStatus = "inactive",
                                then="INACTIVE",
                                else="STATUS_UNKNOWN"
                            )
                        ),

                        else="UNSUPPORTED_TOOL"
                    )
                )
            )
        ) AS FirewallState,

        IptablesFilterBlock,
        RawOutput,
        Stderr,
        ReturnCode

    FROM FirewallIndicators


-- ------------------------------------------------------------
-- 5. Add evidence-based review context
-- ------------------------------------------------------------

LET FirewallReviewed <=
    SELECT
        ClientId,
        Fqdn,
        Tool,
        FirewallBackend,
        CollectionStatus,
        FirewallState,

        FilterInputPolicy,
        FilterForwardPolicy,
        FilterOutputPolicy,

        FilterTablePresent,
        ExplicitFilterRulesPresent,
        DenyRuleEvidence,
        AllowRuleEvidence,

        NftRulesetPresent,
        NftDenyEvidence,

        UFWStatus,
        UFWDefaultPolicies,
        UFWLogging,

        if(
            condition=FirewallState = "COMMAND_FAILED",
            then="COLLECTION_REVIEW_REQUIRED",

            else=if(
                condition=
                    FirewallState =
                        "DEFAULT_ACCEPT_NO_FILTER_RULES",

                then="NO_RESTRICTIVE_IPV4_IPTABLES_FILTERING_OBSERVED",

                else=if(
                    condition=
                        FirewallState =
                            "RESTRICTIVE_INPUT_DEFAULT_POLICY",

                    then="RESTRICTIVE_INPUT_POLICY_PRESENT",

                    else=if(
                        condition=
                            FirewallState =
                                "FILTER_RULESET_PRESENT",

                        then="COMPARE_IPTABLES_RULESET_WITH_APPROVED_BASELINE",

                        else=if(
                            condition=
                                FirewallState =
                                    "FILTER_TABLE_NOT_RETURNED",

                            then="IPTABLES_FILTER_TABLE_REVIEW",

                            else=if(
                                condition=
                                    FirewallBackend = "NFTABLES"
                                    AND FirewallState =
                                        "EMPTY_RULESET",

                                then="NO_NATIVE_NFT_RULESET_CONTEXT",

                                else=if(
                                    condition=
                                        FirewallBackend = "NFTABLES"
                                        AND FirewallState =
                                            "RULESET_PRESENT",

                                    then="COMPARE_NFT_RULESET_WITH_APPROVED_BASELINE",

                                    else=if(
                                        condition=
                                            FirewallBackend = "UFW"
                                            AND FirewallState = "INACTIVE",

                                        then="UFW_FRONTEND_INACTIVE_CONTEXT",

                                        else=if(
                                            condition=
                                                FirewallBackend = "UFW"
                                                AND FirewallState = "ACTIVE",

                                            then="COMPARE_UFW_POLICY_WITH_APPROVED_BASELINE",

                                            else="MANUAL_FIREWALL_REVIEW"
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS ReviewContext,

        if(
            condition=
                FirewallState = "COMMAND_FAILED"
                OR FirewallState =
                    "DEFAULT_ACCEPT_NO_FILTER_RULES"
                OR FirewallState =
                    "FILTER_TABLE_NOT_RETURNED"
                OR FirewallState =
                    "FILTER_TABLE_REVIEW_REQUIRED"
                OR FirewallState =
                    "STATUS_UNKNOWN",

            then=TRUE,

            else=if(
                condition=
                    FirewallState = "FILTER_RULESET_PRESENT"
                    OR FirewallState = "RULESET_PRESENT"
                    OR FirewallState = "ACTIVE",

                then=TRUE,
                else=FALSE
            )
        ) AS ReviewRequired,

        IptablesFilterBlock,
        RawOutput,
        Stderr,
        ReturnCode,

        FALSE AS FindingGenerated,
        FALSE AS RiskScoreEligible

    FROM FirewallStates


-- ------------------------------------------------------------
-- 6. Final output
-- ------------------------------------------------------------

SELECT
    ClientId,
    Fqdn,
    Tool,
    FirewallBackend,

    CollectionStatus,
    FirewallState,

    FilterInputPolicy,
    FilterForwardPolicy,
    FilterOutputPolicy,

    FilterTablePresent,
    ExplicitFilterRulesPresent,
    DenyRuleEvidence,
    AllowRuleEvidence,

    NftRulesetPresent,
    NftDenyEvidence,

    UFWStatus,
    UFWDefaultPolicies,
    UFWLogging,

    ReviewContext,
    ReviewRequired,

    RawOutput,
    Stderr,
    ReturnCode,

    FindingGenerated,
    RiskScoreEligible

FROM FirewallReviewed

ORDER BY
    ClientId
```

## Cell 18 (markdown)

# Suspicious Listening Services

Behavior-based review of Linux listening sockets and their owning processes. The analysis prioritizes interactive listener utilities, ad-hoc file servers, temporary executable paths, privileged execution, and exposure on all interfaces. Port-only matches remain review context and do not independently contribute to the Master Risk Score.

## Cell 19 (vql)

```vql
-- ============================================================
-- Suspicious Listening Services
-- Telemetry Compatibility: Direct
-- Review State: Needs Tuning
-- Risk Weight: 2 per unique eligible socket
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- 1. Read all listening sockets
-- ------------------------------------------------------------

LET ListeningRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Status,

        format(
            format="%v",
            args=[Laddr]
        ) AS LocalAddress,

        format(
            format="%v",
            args=[Lport]
        ) AS LocalPort,

        Pid,

        ProcInfo.Name AS ProcessName,
        ProcInfo.Exe AS ProcessPath,
        ProcInfo.Username AS Username,
        ProcInfo.CommandLine AS CommandLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ '''(?i)^LISTEN(ING)?$'''


-- ------------------------------------------------------------
-- 2. Normalize socket exposure and basic context
-- ------------------------------------------------------------

LET ListeningNormalized <=
    SELECT
        *,

        if(
            condition=LocalAddress =~
                '''^(0[.]0[.]0[.]0|::|0:0:0:0:0:0:0:0|[*])$''',

            then="ALL_INTERFACES",

            else=if(
                condition=
                    LocalAddress =~ '''^127[.]'''
                    OR LocalAddress = "::1",

                then="LOOPBACK_ONLY",
                else="SPECIFIC_INTERFACE"
            )
        ) AS BindScope,

        if(
            condition=LocalPort =~
                '''^(4444|1337|31337|8080|9001|9002)$''',

            then=TRUE,
            else=FALSE
        ) AS WatchedPortEvidence,

        if(
            condition=Username =~ '''(?i)^root$''',
            then=TRUE,
            else=FALSE
        ) AS RootOwned,

        format(
            format="%v|%v|%v|%v|%v",
            args=[
                ClientId,
                LocalAddress,
                LocalPort,
                Pid,
                ProcessName
            ]
        ) AS SocketKey

    FROM ListeningRaw


-- ------------------------------------------------------------
-- 3. Detect behavior-based indicators
-- ------------------------------------------------------------

LET ListeningSignals <=
    SELECT
        *,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(nc|ncat|netcat|socat|cryptcat)$'''

                OR ProcessPath =~
                    '''(?i)/(nc([.]openbsd|[.]traditional)?|ncat|netcat|socat|cryptcat)$'''

                OR CommandLine =~
                    '''(?i)(^|[[:space:]/])(nc|ncat|netcat|socat|cryptcat)([[:space:]]|$)''',

            then=TRUE,
            else=FALSE
        ) AS ListenerToolEvidence,

        if(
            condition=
                CommandLine =~
                    '''(?i)(^|[[:space:]/])python(2|3)?([.][0-9]+)?[[:space:]]+-m[[:space:]]+(http[.]server|SimpleHTTPServer)([[:space:]]|$)'''

                OR CommandLine =~
                    '''(?i)(^|[[:space:]/])php([0-9.]+)?[[:space:]]+-S([[:space:]]|$)'''

                OR CommandLine =~
                    '''(?i)(^|[[:space:]/])ruby([[:space:]]|$).*-run.*-e.*httpd'''

                OR CommandLine =~
                    '''(?i)(^|[[:space:]/])busybox[[:space:]]+httpd([[:space:]]|$)''',

            then=TRUE,
            else=FALSE
        ) AS AdHocServerEvidence,

        if(
            condition=ProcessPath =~
                '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)''',

            then=TRUE,
            else=FALSE
        ) AS TemporaryExecutableEvidence,

        if(
            condition=ProcessPath =~
                '''(?i)[(]deleted[)]$''',

            then=TRUE,
            else=FALSE
        ) AS DeletedExecutableEvidence

    FROM ListeningNormalized


-- ------------------------------------------------------------
-- 4. Classify each candidate
-- ------------------------------------------------------------

LET ListeningClassified <=
    SELECT
        *,

        if(
            condition=
                ListenerToolEvidence
                AND BindScope = "ALL_INTERFACES",

            then="INTERACTIVE_LISTENER_TOOL_EXPOSED",

            else=if(
                condition=ListenerToolEvidence,

                then="INTERACTIVE_LISTENER_TOOL",

                else=if(
                    condition=
                        TemporaryExecutableEvidence
                        OR DeletedExecutableEvidence,

                    then="UNTRUSTED_PATH_LISTENER",

                    else=if(
                        condition=
                            AdHocServerEvidence
                            AND BindScope = "ALL_INTERFACES",

                        then="AD_HOC_SERVER_EXPOSED",

                        else=if(
                            condition=AdHocServerEvidence,

                            then="AD_HOC_SERVER_LOCAL_OR_SCOPED",

                            else=if(
                                condition=WatchedPortEvidence,

                                then="WATCHED_PORT_ONLY",
                                else="NORMAL_LISTENER_CONTEXT"
                            )
                        )
                    )
                )
            )
        ) AS DetectionClass

    FROM ListeningSignals


-- ------------------------------------------------------------
-- 5. Assign finding state, severity and risk eligibility
-- ------------------------------------------------------------

LET ListeningScored <=
    SELECT
        *,

        if(
            condition=DetectionClass =~
                '''^(INTERACTIVE_LISTENER_TOOL_EXPOSED|INTERACTIVE_LISTENER_TOOL|UNTRUSTED_PATH_LISTENER|AD_HOC_SERVER_EXPOSED)$''',

            then=TRUE,
            else=FALSE
        ) AS FindingGenerated,

        if(
            condition=
                DetectionClass =~
                    '''^(INTERACTIVE_LISTENER_TOOL_EXPOSED|INTERACTIVE_LISTENER_TOOL|UNTRUSTED_PATH_LISTENER)$'''

                OR (
                    DetectionClass = "AD_HOC_SERVER_EXPOSED"
                    AND RootOwned
                ),

            then="HIGH",

            else=if(
                condition=DetectionClass =~ '''^AD_HOC_SERVER''',

                then="MEDIUM",

                else=if(
                    condition=DetectionClass = "WATCHED_PORT_ONLY",

                    then="INFO",
                    else="INFO"
                )
            )
        ) AS Severity,

        if(
            condition=ListenerToolEvidence,

            then="HIGH",

            else=if(
                condition=
                    TemporaryExecutableEvidence
                    OR DeletedExecutableEvidence
                    OR AdHocServerEvidence,

                then="MEDIUM",
                else="LOW"
            )
        ) AS Confidence,

        if(
            condition=
                DetectionClass =
                    "INTERACTIVE_LISTENER_TOOL_EXPOSED",

            then="Netcat-style listener exposed on all interfaces",

            else=if(
                condition=
                    DetectionClass =
                        "INTERACTIVE_LISTENER_TOOL",

                then="Netcat-style process owns a listening socket",

                else=if(
                    condition=
                        DetectionClass =
                            "UNTRUSTED_PATH_LISTENER",

                    then="Listening process executed from a temporary or deleted path",

                    else=if(
                        condition=
                            DetectionClass =
                                "AD_HOC_SERVER_EXPOSED"
                            AND RootOwned,

                        then="Root-owned ad-hoc server exposed on all interfaces",

                        else=if(
                            condition=
                                DetectionClass =
                                    "AD_HOC_SERVER_EXPOSED",

                            then="Ad-hoc server exposed on all interfaces",

                            else=if(
                                condition=
                                    DetectionClass =
                                        "AD_HOC_SERVER_LOCAL_OR_SCOPED",

                                then="Ad-hoc server requires ownership and purpose review",

                                else="Watched port without supporting suspicious process behavior"
                            )
                        )
                    )
                )
            )
        ) AS Reason,

        "Direct" AS TelemetryCompatibility,
        "Needs Tuning" AS ReviewState

    FROM ListeningClassified

    WHERE DetectionClass != "NORMAL_LISTENER_CONTEXT"


-- ------------------------------------------------------------
-- 6. Deduplicate and produce final output
-- ------------------------------------------------------------

LET DeduplicatedListeners <=
    SELECT *

    FROM ListeningScored

    GROUP BY SocketKey


SELECT
    ClientId,
    Fqdn,

    Status,
    LocalAddress,
    LocalPort,
    BindScope,

    Pid,
    ProcessName,
    ProcessPath,
    Username,
    CommandLine,

    DetectionClass,
    Severity,
    Confidence,
    Reason,

    ListenerToolEvidence,
    AdHocServerEvidence,
    TemporaryExecutableEvidence,
    DeletedExecutableEvidence,
    WatchedPortEvidence,
    RootOwned,

    FindingGenerated,

    FindingGenerated AS RiskScoreEligible,

    if(
        condition=FindingGenerated,
        then=2,
        else=0
    ) AS RiskWeight,

    TelemetryCompatibility,
    ReviewState

FROM DeduplicatedListeners

ORDER BY
    ClientId
```

## Cell 20 (markdown)

# Suspicious Network Tools or Shells

Behavior-based analysis of established Linux network sessions associated with shells, interpreters, tunneling utilities, Netcat/Socat, temporary executables, SSH port forwarding, and high-risk transfer commands. Listening sockets already evaluated by the Suspicious Listening Services cell remain supporting context and are excluded from this cell's risk contribution.

## Cell 21 (vql)

```vql
-- ============================================================
-- Suspicious Network Tools or Shells
-- Telemetry Compatibility: Direct, volatile snapshot
-- Risk Weight: 2 per unique eligible network process
-- Listener Risk: Handled by Suspicious Listening Services
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- 1. Read active network sockets and process context
-- ------------------------------------------------------------

LET NetworkRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Status,

        format(
            format="%v",
            args=[Laddr]
        ) AS LocalAddress,

        format(
            format="%v",
            args=[Lport]
        ) AS LocalPort,

        format(
            format="%v",
            args=[Raddr]
        ) AS RemoteAddress,

        format(
            format="%v",
            args=[Rport]
        ) AS RemotePort,

        Pid,

        ProcInfo.Name AS ProcessName,
        ProcInfo.Exe AS ProcessPath,
        ProcInfo.Username AS Username,
        ProcInfo.CommandLine AS CommandLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~
        '''(?i)(ESTAB|ESTABLISHED|LISTEN|LISTENING)'''


-- ------------------------------------------------------------
-- 2. Normalize connection state and remote-address scope
-- ------------------------------------------------------------

LET NetworkNormalized <=
    SELECT
        *,

        if(
            condition=Status =~ '''(?i)^ESTAB''',
            then="ESTABLISHED",
            else="LISTENING"
        ) AS ConnectionState,

        if(
            condition=
                RemoteAddress =~ '''^127[.]'''
                OR RemoteAddress = "::1",

            then="LOOPBACK",

            else=if(
                condition=
                    RemoteAddress =~ '''^10[.]'''
                    OR RemoteAddress =~
                        '''^172[.](1[6-9]|2[0-9]|3[01])[.]'''
                    OR RemoteAddress =~ '''^192[.]168[.]'''
                    OR RemoteAddress =~ '''(?i)^f[cd][0-9a-f]{2}:''',

                then="PRIVATE_INTERNAL",

                else=if(
                    condition=
                        RemoteAddress =~ '''^169[.]254[.]'''
                        OR RemoteAddress =~ '''(?i)^fe[89ab][0-9a-f]:''',

                    then="LINK_LOCAL",

                    else=if(
                        condition=
                            RemoteAddress = "0.0.0.0"
                            OR RemoteAddress = "::"
                            OR RemoteAddress = "",

                        then="NOT_APPLICABLE",
                        else="PUBLIC_OR_OTHER"
                    )
                )
            )
        ) AS RemoteScope,

        format(
            format="%v|%v|%v",
            args=[
                ClientId,
                Pid,
                ProcessName
            ]
        ) AS NetworkProcessKey,

        format(
            format="%v|%v|%v|%v|%v|%v",
            args=[
                ClientId,
                LocalAddress,
                LocalPort,
                RemoteAddress,
                RemotePort,
                Pid
            ]
        ) AS SocketKey

    FROM NetworkRaw


-- ------------------------------------------------------------
-- 3. Identify process and tool families
-- ------------------------------------------------------------

LET NetworkFamilies <=
    SELECT
        *,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(bash|sh|dash|zsh|ksh|fish)$'''

                OR ProcessPath =~
                    '''(?i)/(bash|sh|dash|zsh|ksh|fish)$''',

            then=TRUE,
            else=FALSE
        ) AS ShellProcessEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(python([0-9]+([.][0-9]+)*)?|perl|ruby)$'''

                OR ProcessPath =~
                    '''(?i)/(python([0-9]+([.][0-9]+)*)?|perl|ruby)$''',

            then=TRUE,
            else=FALSE
        ) AS InterpreterProcessEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(nc|nc[.]openbsd|nc[.]traditional|ncat|netcat|socat|cryptcat)$'''

                OR ProcessPath =~
                    '''(?i)/(nc([.]openbsd|[.]traditional)?|ncat|netcat|socat|cryptcat)$''',

            then=TRUE,
            else=FALSE
        ) AS NetUtilityEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|cloudflared|sshuttle)$'''

                OR ProcessPath =~
                    '''(?i)/(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|cloudflared|sshuttle)$''',

            then=TRUE,
            else=FALSE
        ) AS DedicatedTunnelToolEvidence,

        if(
            condition=
                ProcessName =~ '''(?i)^(curl|wget)$'''
                OR ProcessPath =~ '''(?i)/(curl|wget)$''',

            then=TRUE,
            else=FALSE
        ) AS TransferToolEvidence,

        if(
            condition=
                ProcessName =~ '''(?i)^ssh$'''
                OR ProcessPath =~ '''(?i)/ssh$''',

            then=TRUE,
            else=FALSE
        ) AS SSHProcessEvidence,

        if(
            condition=ProcessPath =~
                '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)''',

            then=TRUE,
            else=FALSE
        ) AS TemporaryExecutableEvidence,

        if(
            condition=ProcessPath =~ '''(?i)[(]deleted[)]$''',
            then=TRUE,
            else=FALSE
        ) AS DeletedExecutableEvidence

    FROM NetworkNormalized


-- ------------------------------------------------------------
-- 4. Detect stronger command-line behaviors
-- ------------------------------------------------------------

LET NetworkSignals <=
    SELECT
        *,

        if(
            condition=
                ConnectionState = "ESTABLISHED"
                AND ShellProcessEvidence

                AND CommandLine =~
                    '''(?i)(/dev/(tcp|udp)/|(^|[[:space:]])(bash|sh|dash|zsh|ksh)[[:space:]]+-i([[:space:]]|$)|[0-9]?>&[0-9]|[0-9]?<&[0-9])''',

            then=TRUE,
            else=FALSE
        ) AS ExplicitShellChannelEvidence,

        if(
            condition=
                ConnectionState = "ESTABLISHED"
                AND InterpreterProcessEvidence

                AND CommandLine =~
                    '''(?i)(socket|TCPSocket|IO::Socket)'''

                AND CommandLine =~
                    '''(?i)(connect|create_connection)'''

                AND CommandLine =~
                    '''(?i)(subprocess|pty|dup2|exec|spawn|/bin/(bash|sh))''',

            then=TRUE,
            else=FALSE
        ) AS InterpreterSocketShellEvidence,

        if(
            condition=
                SSHProcessEvidence

                AND (
                    CommandLine =~
                        '''(?i)(^|[[:space:]])-R([[:space:]]|[^[:space:]]+)'''

                    OR CommandLine =~
                        '''(?i)-o[[:space:]]*RemoteForward([=[:space:]]|$)'''
                ),

            then=TRUE,
            else=FALSE
        ) AS SSHRemoteForwardEvidence,

        if(
            condition=
                SSHProcessEvidence

                AND (
                    CommandLine =~
                        '''(?i)(^|[[:space:]])-(L|D|W|w)([[:space:]]|[^[:space:]]+)'''

                    OR CommandLine =~
                        '''(?i)-o[[:space:]]*(LocalForward|DynamicForward|ProxyCommand|ProxyJump)([=[:space:]]|$)'''
                ),

            then=TRUE,
            else=FALSE
        ) AS SSHOtherForwardEvidence,

        if(
            condition=
                CommandLine =~ '''(?i)(curl|wget)'''

                AND CommandLine =~
                    '''(?i)[|][[:space:]]*(sudo[[:space:]]+)?(bash|sh|zsh|python|perl)([[:space:]]|$)''',

            then=TRUE,
            else=FALSE
        ) AS DownloadExecuteEvidence,

        if(
            condition=
                TransferToolEvidence

                AND (
                    CommandLine =~
                        '''(?i)(^|[[:space:]])(--upload-file|-T)([=[:space:]]|$)'''

                    OR CommandLine =~
                        '''(?i)--data-binary[=[:space:]]+@'''

                    OR CommandLine =~
                        '''(?i)(--form|-F)[=[:space:]]+[^[:space:]]*=@'''

                    OR CommandLine =~
                        '''(?i)(--post-file|--body-file)([=[:space:]]|$)'''
                ),

            then=TRUE,
            else=FALSE
        ) AS UploadTransferEvidence

    FROM NetworkFamilies


-- ------------------------------------------------------------
-- 5. Classify candidates
-- ------------------------------------------------------------

LET NetworkClassified <=
    SELECT
        *,

        if(
            condition=
                ConnectionState = "LISTENING"

                AND (
                    ShellProcessEvidence
                    OR InterpreterProcessEvidence
                    OR NetUtilityEvidence
                    OR DedicatedTunnelToolEvidence
                    OR TransferToolEvidence
                    OR TemporaryExecutableEvidence
                    OR DeletedExecutableEvidence
                ),

            then="LISTENER_CONTEXT_HANDLED_BY_PREVIOUS_CELL",

            else=if(
                condition=ConnectionState != "ESTABLISHED",

                then="NOT_IN_SCOPE",

                else=if(
                    condition=ExplicitShellChannelEvidence,

                    then="EXPLICIT_SHELL_NETWORK_CHANNEL",

                    else=if(
                        condition=InterpreterSocketShellEvidence,

                        then="INTERPRETER_SOCKET_SHELL_CHANNEL",

                        else=if(
                            condition=DedicatedTunnelToolEvidence,

                            then="DEDICATED_TUNNEL_TOOL_SESSION",

                            else=if(
                                condition=SSHRemoteForwardEvidence,

                                then="SSH_REMOTE_FORWARDING_CONTEXT",

                                else=if(
                                    condition=SSHOtherForwardEvidence,

                                    then="SSH_FORWARDING_CONTEXT",

                                    else=if(
                                        condition=NetUtilityEvidence,

                                        then="NETCAT_OR_SOCAT_SESSION",

                                        else=if(
                                            condition=DownloadExecuteEvidence,

                                            then="DOWNLOAD_AND_EXECUTE_CHANNEL",

                                            else=if(
                                                condition=
                                                    TemporaryExecutableEvidence
                                                    OR DeletedExecutableEvidence,

                                                then="TEMP_OR_DELETED_PATH_NETWORK_SESSION",

                                                else=if(
                                                    condition=UploadTransferEvidence,

                                                    then="UPLOAD_TRANSFER_CONTEXT",

                                                    else=if(
                                                        condition=TransferToolEvidence,

                                                        then="GENERIC_TRANSFER_TOOL_CONTEXT",

                                                        else=if(
                                                            condition=
                                                                ShellProcessEvidence
                                                                OR InterpreterProcessEvidence,

                                                            then="GENERIC_SHELL_OR_INTERPRETER_CONTEXT",
                                                            else="NOT_IN_SCOPE"
                                                        )
                                                    )
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS DetectionClass

    FROM NetworkSignals


-- ------------------------------------------------------------
-- 6. Set finding, severity and ATT&CK context
-- ------------------------------------------------------------

LET NetworkScored <=
    SELECT
        *,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL_NETWORK_CHANNEL|INTERPRETER_SOCKET_SHELL_CHANNEL|DEDICATED_TUNNEL_TOOL_SESSION|NETCAT_OR_SOCAT_SESSION|DOWNLOAD_AND_EXECUTE_CHANNEL|TEMP_OR_DELETED_PATH_NETWORK_SESSION)$''',

            then=TRUE,
            else=FALSE
        ) AS FindingGenerated,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL_NETWORK_CHANNEL|INTERPRETER_SOCKET_SHELL_CHANNEL|DEDICATED_TUNNEL_TOOL_SESSION|NETCAT_OR_SOCAT_SESSION|DOWNLOAD_AND_EXECUTE_CHANNEL|TEMP_OR_DELETED_PATH_NETWORK_SESSION)$''',

            then="HIGH",

            else=if(
                condition=DetectionClass =~
                    '''^(SSH_REMOTE_FORWARDING_CONTEXT|SSH_FORWARDING_CONTEXT|UPLOAD_TRANSFER_CONTEXT)$''',

                then="MEDIUM",
                else="INFO"
            )
        ) AS Severity,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL_NETWORK_CHANNEL|INTERPRETER_SOCKET_SHELL_CHANNEL|DEDICATED_TUNNEL_TOOL_SESSION|NETCAT_OR_SOCAT_SESSION|DOWNLOAD_AND_EXECUTE_CHANNEL)$''',

            then="HIGH",

            else=if(
                condition=DetectionClass =~
                    '''^(TEMP_OR_DELETED_PATH_NETWORK_SESSION|SSH_REMOTE_FORWARDING_CONTEXT|SSH_FORWARDING_CONTEXT|UPLOAD_TRANSFER_CONTEXT)$''',

                then="MEDIUM",
                else="LOW"
            )
        ) AS Confidence,

        if(
            condition=DetectionClass = "EXPLICIT_SHELL_NETWORK_CHANNEL",

            then="Established socket owned by a shell with interactive or socket-redirection behavior",

            else=if(
                condition=DetectionClass =
                    "INTERPRETER_SOCKET_SHELL_CHANNEL",

                then="Interpreter command combines socket connection and shell-execution primitives",

                else=if(
                    condition=DetectionClass =
                        "DEDICATED_TUNNEL_TOOL_SESSION",

                    then="Established session owned by a dedicated tunneling or proxy utility",

                    else=if(
                        condition=DetectionClass =
                            "SSH_REMOTE_FORWARDING_CONTEXT",

                        then="SSH remote port forwarding requires comparison with administrative policy",

                        else=if(
                            condition=DetectionClass =
                                "SSH_FORWARDING_CONTEXT",

                            then="SSH local, dynamic, or stream forwarding requires baseline review",

                            else=if(
                                condition=DetectionClass =
                                    "NETCAT_OR_SOCAT_SESSION",

                                then="Established network session owned by Netcat or Socat",

                                else=if(
                                    condition=DetectionClass =
                                        "DOWNLOAD_AND_EXECUTE_CHANNEL",

                                    then="Command combines remote download with interpreter execution",

                                    else=if(
                                        condition=DetectionClass =
                                            "TEMP_OR_DELETED_PATH_NETWORK_SESSION",

                                        then="Established session owned by a temporary or deleted executable",

                                        else=if(
                                            condition=DetectionClass =
                                                "UPLOAD_TRANSFER_CONTEXT",

                                            then="File-upload behavior requires destination and business-purpose review",

                                            else=if(
                                                condition=DetectionClass =
                                                    "GENERIC_TRANSFER_TOOL_CONTEXT",

                                                then="Ordinary curl or wget transfer without stronger suspicious behavior",

                                                else=if(
                                                    condition=DetectionClass =
                                                        "GENERIC_SHELL_OR_INTERPRETER_CONTEXT",

                                                    then="Shell or interpreter owns an established socket without explicit malicious command evidence",

                                                    else="Listener already evaluated by Suspicious Listening Services"
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS Reason,

        if(
            condition=DetectionClass =
                "EXPLICIT_SHELL_NETWORK_CHANNEL",

            then="T1059.004",

            else=if(
                condition=DetectionClass =
                    "INTERPRETER_SOCKET_SHELL_CHANNEL"
                    AND ProcessName =~ '''(?i)^python''',

                then="T1059.006",

                else=if(
                    condition=DetectionClass =~
                        '''^(DEDICATED_TUNNEL_TOOL_SESSION|SSH_REMOTE_FORWARDING_CONTEXT|SSH_FORWARDING_CONTEXT)$''',

                    then="T1572",

                    else=if(
                        condition=DetectionClass =
                            "DOWNLOAD_AND_EXECUTE_CHANNEL",

                        then="T1105",
                        else="UNASSIGNED_FROM_SOCKET_EVIDENCE"
                    )
                )
            )
        ) AS ATTACKTechnique,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL_NETWORK_CHANNEL|INTERPRETER_SOCKET_SHELL_CHANNEL|DEDICATED_TUNNEL_TOOL_SESSION|NETCAT_OR_SOCAT_SESSION|DOWNLOAD_AND_EXECUTE_CHANNEL|TEMP_OR_DELETED_PATH_NETWORK_SESSION|SSH_REMOTE_FORWARDING_CONTEXT|SSH_FORWARDING_CONTEXT|UPLOAD_TRANSFER_CONTEXT)$''',

            then=TRUE,
            else=FALSE
        ) AS ReviewRequired

    FROM NetworkClassified

    WHERE DetectionClass != "NOT_IN_SCOPE"


-- ------------------------------------------------------------
-- 7. Remove duplicate socket records
-- ------------------------------------------------------------

LET DeduplicatedNetworkSessions <=
    SELECT *

    FROM NetworkScored

    GROUP BY SocketKey


-- ------------------------------------------------------------
-- 8. Final output
-- ------------------------------------------------------------

SELECT
    ClientId,
    Fqdn,

    ConnectionState,
    LocalAddress,
    LocalPort,
    RemoteAddress,
    RemotePort,
    RemoteScope,

    Pid,
    ProcessName,
    ProcessPath,
    Username,
    CommandLine,

    DetectionClass,
    Severity,
    Confidence,
    Reason,
    ATTACKTechnique,

    ShellProcessEvidence,
    InterpreterProcessEvidence,
    NetUtilityEvidence,
    DedicatedTunnelToolEvidence,

    ExplicitShellChannelEvidence,
    InterpreterSocketShellEvidence,

    SSHRemoteForwardEvidence,
    SSHOtherForwardEvidence,

    DownloadExecuteEvidence,
    UploadTransferEvidence,

    TemporaryExecutableEvidence,
    DeletedExecutableEvidence,

    ReviewRequired,
    FindingGenerated,

    FindingGenerated AS RiskScoreEligible,

    if(
        condition=FindingGenerated,
        then=2,
        else=0
    ) AS RiskWeight,

    NetworkProcessKey,
    SocketKey,

    "Direct - Volatile Snapshot" AS TelemetryCompatibility,
    "Needs Tuning" AS ReviewState

FROM DeduplicatedNetworkSessions

ORDER BY
    ClientId
```

## Cell 22 (markdown)

# Suspicious External Connections

Reviews established Linux network sessions communicating with public IP addresses. Connections are prioritized using process identity, executable path, command-line behavior, tunneling utilities, Netcat/Socat usage, and watched remote ports. Listening sockets, private destinations, loopback traffic, and special-purpose address ranges are excluded.

## Cell 23 (vql)

```vql
-- ============================================================
-- Suspicious External Connections
-- Telemetry: Direct - Volatile Snapshot
-- Risk Ownership: Suspicious Network Tools or Shells
-- Current Cell Risk Contribution: 0
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- 1. Read established sockets from the raw enriched artifact
-- ------------------------------------------------------------

LET ExternalRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        Status,

        format(
            format="%v",
            args=[Laddr]
        ) AS LocalAddress,

        format(
            format="%v",
            args=[Lport]
        ) AS LocalPort,

        format(
            format="%v",
            args=[Raddr]
        ) AS RemoteAddress,

        format(
            format="%v",
            args=[Rport]
        ) AS RemotePort,

        Pid,

        ProcInfo.Name AS ProcessName,
        ProcInfo.Exe AS ProcessPath,
        ProcInfo.Username AS Username,
        ProcInfo.CommandLine AS CommandLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ '''(?i)^ESTAB'''


-- ------------------------------------------------------------
-- 2. Classify the remote-address scope
-- ------------------------------------------------------------

LET AddressClassified <=
    SELECT
        *,

        if(
            condition=
                RemoteAddress = ""
                OR RemoteAddress = "0.0.0.0"
                OR RemoteAddress = "::"
                OR RemoteAddress =~ '''(?i)<nil>|none''',

            then="NOT_APPLICABLE",

            else=if(
                condition=
                    RemoteAddress =~ '''^127[.]'''
                    OR RemoteAddress = "::1",

                then="LOOPBACK",

                else=if(
                    condition=
                        RemoteAddress =~ '''^10[.]'''
                        OR RemoteAddress =~
                            '''^172[.](1[6-9]|2[0-9]|3[01])[.]'''
                        OR RemoteAddress =~ '''^192[.]168[.]'''
                        OR RemoteAddress =~ '''(?i)^f[cd][0-9a-f]{2}:''',

                    then="PRIVATE_INTERNAL",

                    else=if(
                        condition=
                            RemoteAddress =~
                                '''^100[.](6[4-9]|[789][0-9]|1[01][0-9]|12[0-7])[.]'''
                            OR RemoteAddress =~ '''^169[.]254[.]'''
                            OR RemoteAddress =~
                                '''(?i)^fe[89ab][0-9a-f]:''',

                        then="SHARED_OR_LINK_LOCAL",

                        else=if(
                            condition=
                                RemoteAddress =~ '''^0[.]'''
                                OR RemoteAddress =~ '''^192[.]0[.]0[.]'''
                                OR RemoteAddress =~ '''^192[.]0[.]2[.]'''
                                OR RemoteAddress =~ '''^198[.](18|19)[.]'''
                                OR RemoteAddress =~
                                    '''^198[.]51[.]100[.]'''
                                OR RemoteAddress =~
                                    '''^203[.]0[.]113[.]'''
                                OR RemoteAddress =~
                                    '''^(22[4-9]|23[0-9]|2[4-5][0-9])[.]'''
                                OR RemoteAddress =~
                                    '''(?i)^2001:db8:'''
                                OR RemoteAddress =~ '''(?i)^ff''',

                            then="SPECIAL_OR_RESERVED",

                            else=if(
                                condition=
                                    RemoteAddress =~
                                        '''(?i)^::ffff:(10[.]|127[.]|169[.]254[.]|172[.](1[6-9]|2[0-9]|3[01])[.]|192[.]168[.])''',

                                then="PRIVATE_MAPPED_IPV4",

                                else="PUBLIC_OR_OTHER"
                            )
                        )
                    )
                )
            )
        ) AS DestinationScope,

        format(
            format="%v|%v|%v",
            args=[
                ClientId,
                Pid,
                ProcessName
            ]
        ) AS NetworkProcessKey,

        format(
            format="%v|%v|%v|%v|%v|%v",
            args=[
                ClientId,
                LocalAddress,
                LocalPort,
                RemoteAddress,
                RemotePort,
                Pid
            ]
        ) AS SocketKey

    FROM ExternalRaw


-- ------------------------------------------------------------
-- 3. Keep only sessions to publicly routable destinations
-- ------------------------------------------------------------

LET PublicSessions <=
    SELECT *

    FROM AddressClassified

    WHERE DestinationScope = "PUBLIC_OR_OTHER"


-- ------------------------------------------------------------
-- 4. Identify process and command-line evidence
-- ------------------------------------------------------------

LET ExternalSignals <=
    SELECT
        *,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(nc|nc[.]openbsd|nc[.]traditional|ncat|netcat|socat|cryptcat)$'''

                OR ProcessPath =~
                    '''(?i)/(nc([.]openbsd|[.]traditional)?|ncat|netcat|socat|cryptcat)$''',

            then=TRUE,
            else=FALSE
        ) AS NetUtilityEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|sshuttle|cloudflared)$'''

                OR ProcessPath =~
                    '''(?i)/(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|sshuttle|cloudflared)$''',

            then=TRUE,
            else=FALSE
        ) AS TunnelToolEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(bash|sh|dash|zsh|ksh)$'''

                AND CommandLine =~
                    '''(?i)(/dev/(tcp|udp)/|[[:space:]]+-i([[:space:]]|$)|[0-9]?>&[0-9]|[0-9]?<&[0-9])''',

            then=TRUE,
            else=FALSE
        ) AS ExplicitShellChannelEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(python([0-9.]+)?|perl|ruby)$'''

                AND CommandLine =~
                    '''(?i)(socket|TCPSocket|IO::Socket)'''

                AND CommandLine =~
                    '''(?i)(connect|create_connection)'''

                AND CommandLine =~
                    '''(?i)(subprocess|pty|dup2|exec|spawn|/bin/(bash|sh))''',

            then=TRUE,
            else=FALSE
        ) AS InterpreterShellEvidence,

        if(
            condition=
                (
                    ProcessName =~ '''(?i)^ssh$'''
                    OR ProcessPath =~ '''(?i)/ssh$'''
                )

                AND CommandLine =~
                    '''(?i)(^|[[:space:]])-(L|R|D)([[:space:]]|[^[:space:]]+)''',

            then=TRUE,
            else=FALSE
        ) AS SSHForwardingEvidence,

        if(
            condition=ProcessPath =~
                '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)''',

            then=TRUE,
            else=FALSE
        ) AS TemporaryExecutableEvidence,

        if(
            condition=ProcessPath =~ '''(?i)[(]deleted[)]$''',

            then=TRUE,
            else=FALSE
        ) AS DeletedExecutableEvidence,

        if(
            condition=RemotePort =~
                '''^(4444|5555|1337|31337|6666|6667|9001|9002)$''',

            then=TRUE,
            else=FALSE
        ) AS WatchedRemotePortEvidence

    FROM PublicSessions


-- ------------------------------------------------------------
-- 5. Classify public sessions
-- ------------------------------------------------------------

LET ExternalClassified <=
    SELECT
        *,

        if(
            condition=
                TemporaryExecutableEvidence
                OR DeletedExecutableEvidence,

            then="PUBLIC_SESSION_FROM_UNTRUSTED_PATH",

            else=if(
                condition=ExplicitShellChannelEvidence,

                then="PUBLIC_EXPLICIT_SHELL_CHANNEL",

                else=if(
                    condition=InterpreterShellEvidence,

                    then="PUBLIC_INTERPRETER_SHELL_CHANNEL",

                    else=if(
                        condition=TunnelToolEvidence,

                        then="PUBLIC_TUNNEL_TOOL_SESSION",

                        else=if(
                            condition=NetUtilityEvidence,

                            then="PUBLIC_NETCAT_OR_SOCAT_SESSION",

                            else=if(
                                condition=SSHForwardingEvidence,

                                then="PUBLIC_SSH_FORWARDING_CONTEXT",

                                else=if(
                                    condition=WatchedRemotePortEvidence,

                                    then="PUBLIC_WATCHED_PORT_CONTEXT",

                                    else="PUBLIC_CONNECTION_REVIEW"
                                )
                            )
                        )
                    )
                )
            )
        ) AS DetectionClass

    FROM ExternalSignals


-- ------------------------------------------------------------
-- 6. Assign severity and finding state
-- ------------------------------------------------------------

LET ExternalScored <=
    SELECT
        *,

        if(
            condition=DetectionClass =~
                '''^(PUBLIC_SESSION_FROM_UNTRUSTED_PATH|PUBLIC_EXPLICIT_SHELL_CHANNEL|PUBLIC_INTERPRETER_SHELL_CHANNEL|PUBLIC_TUNNEL_TOOL_SESSION|PUBLIC_NETCAT_OR_SOCAT_SESSION)$''',

            then=TRUE,
            else=FALSE
        ) AS FindingGenerated,

        if(
            condition=DetectionClass =~
                '''^(PUBLIC_SESSION_FROM_UNTRUSTED_PATH|PUBLIC_EXPLICIT_SHELL_CHANNEL|PUBLIC_INTERPRETER_SHELL_CHANNEL|PUBLIC_TUNNEL_TOOL_SESSION|PUBLIC_NETCAT_OR_SOCAT_SESSION)$''',

            then="HIGH",

            else=if(
                condition=DetectionClass =~
                    '''^(PUBLIC_SSH_FORWARDING_CONTEXT|PUBLIC_WATCHED_PORT_CONTEXT)$''',

                then="MEDIUM",
                else="INFO"
            )
        ) AS Severity,

        if(
            condition=DetectionClass =~
                '''^(PUBLIC_EXPLICIT_SHELL_CHANNEL|PUBLIC_INTERPRETER_SHELL_CHANNEL|PUBLIC_TUNNEL_TOOL_SESSION|PUBLIC_NETCAT_OR_SOCAT_SESSION)$''',

            then="HIGH",

            else=if(
                condition=DetectionClass =
                    "PUBLIC_SESSION_FROM_UNTRUSTED_PATH",

                then="MEDIUM",
                else="LOW"
            )
        ) AS Confidence,

        if(
            condition=DetectionClass =
                "PUBLIC_SESSION_FROM_UNTRUSTED_PATH",

            then="Established public session owned by a temporary or deleted executable",

            else=if(
                condition=DetectionClass =
                    "PUBLIC_EXPLICIT_SHELL_CHANNEL",

                then="Shell process has an established public socket and explicit shell-channel behavior",

                else=if(
                    condition=DetectionClass =
                        "PUBLIC_INTERPRETER_SHELL_CHANNEL",

                    then="Interpreter command combines a public socket with shell-execution primitives",

                    else=if(
                        condition=DetectionClass =
                            "PUBLIC_TUNNEL_TOOL_SESSION",

                        then="Dedicated tunneling utility maintains a public network session",

                        else=if(
                            condition=DetectionClass =
                                "PUBLIC_NETCAT_OR_SOCAT_SESSION",

                            then="Netcat or Socat maintains an established public session",

                            else=if(
                                condition=DetectionClass =
                                    "PUBLIC_SSH_FORWARDING_CONTEXT",

                                then="SSH forwarding to a public destination requires administrative-policy review",

                                else=if(
                                    condition=DetectionClass =
                                        "PUBLIC_WATCHED_PORT_CONTEXT",

                                    then="Public connection uses a watched remote port without stronger process evidence",

                                    else="Established connection to a public destination requires baseline review"
                                )
                            )
                        )
                    )
                )
            )
        ) AS Reason,

        if(
            condition=
                TunnelToolEvidence
                OR SSHForwardingEvidence,

            then="T1572",

            else=if(
                condition=ExplicitShellChannelEvidence,

                then="T1059.004",

                else="UNASSIGNED_FROM_SOCKET_EVIDENCE"
            )
        ) AS ATTACKContext,

        if(
            condition=
                NetUtilityEvidence
                OR TunnelToolEvidence
                OR ExplicitShellChannelEvidence
                OR InterpreterShellEvidence
                OR SSHForwardingEvidence
                OR TemporaryExecutableEvidence
                OR DeletedExecutableEvidence,

            then=TRUE,
            else=FALSE
        ) AS HandledByNetworkToolsCell

    FROM ExternalClassified


-- ------------------------------------------------------------
-- 7. Deduplicate socket records
-- ------------------------------------------------------------

LET DeduplicatedExternal <=
    SELECT *

    FROM ExternalScored

    GROUP BY SocketKey


-- ------------------------------------------------------------
-- 8. Final output
-- ------------------------------------------------------------

SELECT
    ClientId,
    Fqdn,

    Status,
    LocalAddress,
    LocalPort,
    RemoteAddress,
    RemotePort,
    DestinationScope,

    Pid,
    ProcessName,
    ProcessPath,
    Username,
    CommandLine,

    DetectionClass,
    Severity,
    Confidence,
    Reason,
    ATTACKContext,

    NetUtilityEvidence,
    TunnelToolEvidence,
    ExplicitShellChannelEvidence,
    InterpreterShellEvidence,
    SSHForwardingEvidence,
    TemporaryExecutableEvidence,
    DeletedExecutableEvidence,
    WatchedRemotePortEvidence,

    TRUE AS ReviewRequired,
    FindingGenerated,

    -- Risk is owned by the previous behavior-based network cell.
    FALSE AS RiskScoreEligible,
    0 AS RiskWeight,

    if(
        condition=HandledByNetworkToolsCell,
        then="Suspicious Network Tools or Shells",
        else="Review Only"
    ) AS RiskScoreOwner,

    NetworkProcessKey,
    SocketKey,

    "Direct - Volatile Snapshot" AS TelemetryCompatibility,
    "Needs Tuning" AS ReviewState

FROM DeduplicatedExternal

ORDER BY
    ClientId
```

## Cell 24 (markdown)

# Suspicious DNS Configuration

Reviews Linux DNS configuration for public or unknown resolvers, temporary configuration paths, suspicious DNS tunneling tool references, unsafe resolver values, and proxy or tunneling directives. Public resolvers are treated as policy-review context unless organizational DNS policy explicitly prohibits them.

## Cell 25 (vql)

```vql
-- ============================================================
-- Suspicious DNS Configuration
-- Telemetry: Direct configuration state
-- Threat attribution: Supporting only
-- Risk Weight: 2 for strong configuration evidence
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ------------------------------------------------------------
-- 1. Read DNS configuration results
-- ------------------------------------------------------------

LET DNSRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        format(
            format="%v",
            args=[Path]
        ) AS ConfigPath,

        format(
            format="%v",
            args=[Line]
        ) AS ConfigLine,

        Severity AS ArtifactSeverity,
        Reason AS ArtifactReason

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/DNSConfigReview"
    )


-- ------------------------------------------------------------
-- 2. Extract resolver address
-- Supports resolv.conf, systemd-resolved and similar formats
-- ------------------------------------------------------------

LET DNSParsed <=
    SELECT
        *,

        parse_string_with_regex(
            string=ConfigLine,
            regex=[
                '''^[[:space:]]*nameserver[[:space:]]+(?P<ResolverAddress>[^#; \t]+)''',
                '''^[[:space:]]*(DNS|FallbackDNS)[[:space:]]*=[[:space:]]*(?P<ResolverAddress>[^#; \t]+)''',
                '''^[[:space:]]*(dns|server)[[:space:]]*=[[:space:]]*(?P<ResolverAddress>[^#; ,\t]+)'''
            ]
        ).ResolverAddress AS ResolverAddress

    FROM DNSRaw


-- ------------------------------------------------------------
-- 3. Identify configuration signals
-- ------------------------------------------------------------

LET DNSSignals <=
    SELECT
        *,

        if(
            condition=ConfigLine =~
                '''^[[:space:]]*($|#|;)''',
            then=FALSE,
            else=TRUE
        ) AS ActiveLineEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)^[[:space:]]*(nameserver[[:space:]]+|(DNS|FallbackDNS|dns|server)[[:space:]]*=)''',
            then=TRUE,
            else=FALSE
        ) AS ResolverDirectiveEvidence,

        if(
            condition=ConfigPath =~
                '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)''',
            then=TRUE,
            else=FALSE
        ) AS TemporaryConfigPathEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)^[[:space:]]*(conf-file|resolv-file|addn-hosts|hostsdir|servers-file)[[:space:]]*=.*(/tmp/|/var/tmp/|/dev/shm/)''',
            then=TRUE,
            else=FALSE
        ) AS TemporaryConfigReferenceEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)(^|[^a-z0-9_-])(iodine|dnscat2?|dns2tcp(c|d)?|heyoka|godoh|dns-exfil)([^a-z0-9_-]|$)''',
            then=TRUE,
            else=FALSE
        ) AS DNSTunnelToolEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)(proxy|tunnel|forward-proxy|dns-over-https|dns-over-tls|doh|dot)''',
            then=TRUE,
            else=FALSE
        ) AS ProxyOrTunnelKeywordEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)(malware|command.?and.?control|c2-server|exfiltration)''',
            then=TRUE,
            else=FALSE
        ) AS ThreatKeywordEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)(^|[^0-9])(8[.]8[.]8[.]8|8[.]8[.]4[.]4|1[.]1[.]1[.]1|1[.]0[.]0[.]1|9[.]9[.]9[.]9|149[.]112[.]112[.]112|208[.]67[.](222[.]222|220[.]220))([^0-9]|$)'''

                OR ConfigLine =~
                    '''(?i)(2001:4860:4860::(8888|8844)|2606:4700:4700::(1111|1001)|2620:fe::(fe|9))''',

            then=TRUE,
            else=FALSE
        ) AS KnownPublicResolverEvidence

    FROM DNSParsed


-- ------------------------------------------------------------
-- 4. Classify resolver address scope
-- ------------------------------------------------------------

LET DNSAddressClassified <=
    SELECT
        *,

        if(
            condition=
                ResolverAddress = ""
                OR NOT ResolverDirectiveEvidence,

            then="NOT_APPLICABLE",

            else=if(
                condition=
                    ResolverAddress =~ '''^127[.]'''
                    OR ResolverAddress = "::1"
                    OR ResolverAddress =~ '''(?i)^fe80:'''
                    OR ResolverAddress =~ '''(?i)^f[cd][0-9a-f]{2}:''',

                then="LOCAL_OR_PRIVATE",

                else=if(
                    condition=
                        ResolverAddress =~ '''^10[.]'''
                        OR ResolverAddress =~
                            '''^172[.](1[6-9]|2[0-9]|3[01])[.]'''
                        OR ResolverAddress =~ '''^192[.]168[.]''',

                    then="LOCAL_OR_PRIVATE",

                    else=if(
                        condition=
                            ResolverAddress =~ '''^0[.]'''
                            OR ResolverAddress =~ '''^169[.]254[.]'''
                            OR ResolverAddress =~
                                '''^(22[4-9]|23[0-9])[.]'''
                            OR ResolverAddress = "255.255.255.255",

                        then="SPECIAL_OR_INVALID",
                        else="EXTERNAL_OR_UNKNOWN"
                    )
                )
            )
        ) AS ResolverScope,

        format(
            format="%v|%v|%v",
            args=[
                ClientId,
                ConfigPath,
                ConfigLine
            ]
        ) AS DNSFindingKey

    FROM DNSSignals


-- ------------------------------------------------------------
-- 5. Classify noteworthy configuration
-- ------------------------------------------------------------

LET DNSClassified <=
    SELECT
        *,

        if(
            condition=ActiveLineEvidence = FALSE,

            then="IGNORED_COMMENT_OR_EMPTY",

            else=if(
                condition=DNSTunnelToolEvidence,

                then="DNS_TUNNEL_TOOL_CONFIGURATION",

                else=if(
                    condition=TemporaryConfigReferenceEvidence,

                    then="TEMPORARY_DNS_CONFIG_REFERENCE",

                    else=if(
                        condition=TemporaryConfigPathEvidence,

                        then="DNS_CONFIG_STORED_IN_TEMP_PATH",

                        else=if(
                            condition=
                                ResolverDirectiveEvidence
                                AND ResolverScope =
                                    "SPECIAL_OR_INVALID",

                            then="INVALID_OR_SPECIAL_RESOLVER",

                            else=if(
                                condition=
                                    ResolverDirectiveEvidence
                                    AND KnownPublicResolverEvidence,

                                then="PUBLIC_RESOLVER_POLICY_REVIEW",

                                else=if(
                                    condition=
                                        ResolverDirectiveEvidence
                                        AND ResolverScope =
                                            "EXTERNAL_OR_UNKNOWN",

                                    then="EXTERNAL_RESOLVER_POLICY_REVIEW",

                                    else=if(
                                        condition=ProxyOrTunnelKeywordEvidence,

                                        then="DNS_PROXY_OR_TUNNEL_REVIEW",

                                        else=if(
                                            condition=ThreatKeywordEvidence,

                                            then="THREAT_KEYWORD_REVIEW",
                                            else="NORMAL_OR_UNRELATED"
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS DetectionClass

    FROM DNSAddressClassified


-- ------------------------------------------------------------
-- 6. Assign finding, severity and reason
-- ------------------------------------------------------------

LET DNSScored <=
    SELECT
        *,

        if(
            condition=DetectionClass =~
                '''^(DNS_TUNNEL_TOOL_CONFIGURATION|TEMPORARY_DNS_CONFIG_REFERENCE)$''',
            then=TRUE,
            else=FALSE
        ) AS FindingGenerated,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="HIGH",

            else=if(
                condition=DetectionClass =~
                    '''^(TEMPORARY_DNS_CONFIG_REFERENCE|DNS_CONFIG_STORED_IN_TEMP_PATH|INVALID_OR_SPECIAL_RESOLVER|EXTERNAL_RESOLVER_POLICY_REVIEW|DNS_PROXY_OR_TUNNEL_REVIEW|THREAT_KEYWORD_REVIEW)$''',

                then="MEDIUM",
                else="INFO"
            )
        ) AS Severity,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="HIGH",

            else=if(
                condition=DetectionClass =
                    "TEMPORARY_DNS_CONFIG_REFERENCE",

                then="MEDIUM",
                else="LOW"
            )
        ) AS Confidence,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="Active DNS configuration references a known DNS tunneling or exfiltration utility",

            else=if(
                condition=DetectionClass =
                    "TEMPORARY_DNS_CONFIG_REFERENCE",

                then="Active DNS configuration references a file stored in a temporary directory",

                else=if(
                    condition=DetectionClass =
                        "DNS_CONFIG_STORED_IN_TEMP_PATH",

                    then="DNS configuration material was collected from an untrusted temporary path",

                    else=if(
                        condition=DetectionClass =
                            "INVALID_OR_SPECIAL_RESOLVER",

                        then="Resolver points to a special-purpose or invalid address",

                        else=if(
                            condition=DetectionClass =
                                "PUBLIC_RESOLVER_POLICY_REVIEW",

                            then="Known public resolver requires comparison with organizational DNS policy",

                            else=if(
                                condition=DetectionClass =
                                    "EXTERNAL_RESOLVER_POLICY_REVIEW",

                                then="External or unknown resolver requires ownership and policy validation",

                                else=if(
                                    condition=DetectionClass =
                                        "DNS_PROXY_OR_TUNNEL_REVIEW",

                                    then="DNS configuration contains proxy, encrypted-DNS, or tunneling terminology",

                                    else="Threat-related keyword requires manual configuration review"
                                )
                            )
                        )
                    )
                )
            )
        ) AS Reason,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="T1071.004 - Supporting Configuration Context",
            else="UNASSIGNED_FROM_CONFIGURATION_ONLY"
        ) AS ATTACKContext,

        if(
            condition=DetectionClass =~
                '''^(PUBLIC_RESOLVER_POLICY_REVIEW|EXTERNAL_RESOLVER_POLICY_REVIEW)$''',
            then=TRUE,
            else=FALSE
        ) AS DNSPolicyReviewRequired

    FROM DNSClassified

    WHERE DetectionClass != "NORMAL_OR_UNRELATED"
      AND DetectionClass != "IGNORED_COMMENT_OR_EMPTY"


-- ------------------------------------------------------------
-- 7. Deduplicate identical configuration lines
-- ------------------------------------------------------------

LET DeduplicatedDNS <=
    SELECT *

    FROM DNSScored

    GROUP BY DNSFindingKey


-- ------------------------------------------------------------
-- 8. Final output
-- ------------------------------------------------------------

SELECT
    ClientId,
    Fqdn,

    ConfigPath,
    ConfigLine,
    ResolverAddress,
    ResolverScope,

    DetectionClass,
    Severity,
    Confidence,
    Reason,
    ATTACKContext,

    DNSTunnelToolEvidence,
    TemporaryConfigReferenceEvidence,
    TemporaryConfigPathEvidence,
    ProxyOrTunnelKeywordEvidence,

    DNSPolicyReviewRequired,
    TRUE AS ReviewRequired,

    FindingGenerated,
    FindingGenerated AS RiskScoreEligible,

    if(
        condition=FindingGenerated,
        then=2,
        else=0
    ) AS RiskWeight,

    DNSFindingKey,

    "Direct Configuration State / Supporting Threat Context"
        AS TelemetryCompatibility,

    "Needs Tuning" AS ReviewState

FROM DeduplicatedDNS

ORDER BY
    ClientId
```

## Cell 26 (markdown)

# Final Findings Detail — Deduplicated Actionable Network Evidence

This section combines suspicious network indicators into one findings table.

It includes suspicious listening ports, suspicious established connections, shell or scripting network activity, suspicious DNS configuration, and firewall-related indicators.

Use this table as the main evidence view for network connection hunting.

## Cell 27 (vql)

```vql
-- ============================================================
-- Final Findings Detail
-- Deduplicated Actionable Network Evidence
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Read raw socket and process evidence
-- ============================================================

LET NetworkRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        format(
            format="%v",
            args=[Status]
        ) AS ConnectionState,

        format(
            format="%v",
            args=[Laddr]
        ) AS LocalAddress,

        format(
            format="%v",
            args=[Lport]
        ) AS LocalPort,

        format(
            format="%v",
            args=[Raddr]
        ) AS RemoteAddress,

        format(
            format="%v",
            args=[Rport]
        ) AS RemotePort,

        Pid,

        format(
            format="%v",
            args=[ProcInfo.Name]
        ) AS ProcessName,

        format(
            format="%v",
            args=[ProcInfo.Exe]
        ) AS ProcessPath,

        format(
            format="%v",
            args=[ProcInfo.Username]
        ) AS Username,

        format(
            format="%v",
            args=[ProcInfo.CommandLine]
        ) AS CommandLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ '''(?i)^(LISTEN|ESTAB)'''


-- ============================================================
-- 2. Identify strong network-process evidence
-- ============================================================

LET NetworkSignals <=
    SELECT
        *,

        if(
            condition=ConnectionState =~ '''(?i)^LISTEN''',
            then=TRUE,
            else=FALSE
        ) AS ListenerEvidence,

        if(
            condition=ConnectionState =~ '''(?i)^ESTAB''',
            then=TRUE,
            else=FALSE
        ) AS EstablishedEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(nc|nc[.]openbsd|nc[.]traditional|ncat|netcat|socat|cryptcat)$'''

                OR ProcessPath =~
                    '''(?i)/(nc([.]openbsd|[.]traditional)?|ncat|netcat|socat|cryptcat)$''',

            then=TRUE,
            else=FALSE
        ) AS NetUtilityEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|sshuttle|cloudflared)$'''

                OR ProcessPath =~
                    '''(?i)/(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|sshuttle|cloudflared)$''',

            then=TRUE,
            else=FALSE
        ) AS TunnelToolEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(bash|sh|dash|zsh|ksh)$'''

                AND CommandLine =~
                    '''(?i)(/dev/(tcp|udp)/|[[:space:]]+-i([[:space:]]|$)|[0-9]?>&[0-9]|[0-9]?<&[0-9])''',

            then=TRUE,
            else=FALSE
        ) AS ExplicitShellChannelEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(python([0-9.]+)?|perl|ruby)$'''

                AND CommandLine =~
                    '''(?i)(socket|TCPSocket|IO::Socket)'''

                AND CommandLine =~
                    '''(?i)(connect|create_connection|bind|listen)'''

                AND CommandLine =~
                    '''(?i)(subprocess|pty|dup2|exec|spawn|/bin/(bash|sh))''',

            then=TRUE,
            else=FALSE
        ) AS InterpreterShellEvidence,

        if(
            condition=
                (
                    ProcessName =~
                        '''(?i)^python([0-9.]+)?$'''

                    AND CommandLine =~
                        '''(?i)(^|[[:space:]])-m[[:space:]]+http[.]server([[:space:]]|$)'''
                )

                OR
                (
                    ProcessName =~ '''(?i)^php$'''

                    AND CommandLine =~
                        '''(?i)(^|[[:space:]])-S[[:space:]]+[^\s]+'''
                ),

            then=TRUE,
            else=FALSE
        ) AS AdHocFileServerEvidence,

        if(
            condition=ProcessPath =~
                '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)''',

            then=TRUE,
            else=FALSE
        ) AS TemporaryExecutableEvidence,

        if(
            condition=ProcessPath =~
                '''(?i)[(]deleted[)]$''',

            then=TRUE,
            else=FALSE
        ) AS DeletedExecutableEvidence,

        format(
            format="%v|%v|%v|%v|%v",
            args=[
                ClientId,
                Pid,
                ProcessName,
                ProcessPath,
                CommandLine
            ]
        ) AS NetworkFindingKey

    FROM NetworkRaw


-- ============================================================
-- 3. Classify actionable network behavior
-- ============================================================

LET NetworkClassified <=
    SELECT
        *,

        if(
            condition=
                ListenerEvidence
                AND NetUtilityEvidence,

            then="NETCAT_OR_SOCAT_LISTENER",

            else=if(
                condition=
                    ListenerEvidence
                    AND TunnelToolEvidence,

                then="TUNNEL_TOOL_LISTENER",

                else=if(
                    condition=
                        ListenerEvidence
                        AND ExplicitShellChannelEvidence,

                    then="EXPLICIT_SHELL_LISTENER",

                    else=if(
                        condition=
                            ListenerEvidence
                            AND InterpreterShellEvidence,

                        then="INTERPRETER_SHELL_LISTENER",

                        else=if(
                            condition=
                                ListenerEvidence
                                AND AdHocFileServerEvidence,

                            then="AD_HOC_FILE_SERVER_LISTENER",

                            else=if(
                                condition=
                                    ListenerEvidence
                                    AND
                                    (
                                        TemporaryExecutableEvidence
                                        OR DeletedExecutableEvidence
                                    ),

                                then="UNTRUSTED_PATH_LISTENER",

                                else=if(
                                    condition=
                                        EstablishedEvidence
                                        AND NetUtilityEvidence,

                                    then="NETCAT_OR_SOCAT_ESTABLISHED",

                                    else=if(
                                        condition=
                                            EstablishedEvidence
                                            AND TunnelToolEvidence,

                                        then="TUNNEL_TOOL_ESTABLISHED",

                                        else=if(
                                            condition=
                                                EstablishedEvidence
                                                AND ExplicitShellChannelEvidence,

                                            then="EXPLICIT_SHELL_ESTABLISHED",

                                            else=if(
                                                condition=
                                                    EstablishedEvidence
                                                    AND InterpreterShellEvidence,

                                                then="INTERPRETER_SHELL_ESTABLISHED",

                                                else=if(
                                                    condition=
                                                        EstablishedEvidence
                                                        AND
                                                        (
                                                            TemporaryExecutableEvidence
                                                            OR DeletedExecutableEvidence
                                                        ),

                                                    then="UNTRUSTED_PATH_ESTABLISHED",
                                                    else="NOT_ACTIONABLE"
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS DetectionClass

    FROM NetworkSignals


-- ============================================================
-- 4. Score and explain network findings
-- ============================================================

LET NetworkScored <=
    SELECT
        *,

        if(
            condition=DetectionClass =~ '''LISTENER$''',
            then="Suspicious Listening Service",
            else="Suspicious Established Network Session"
        ) AS Finding,

        if(
            condition=DetectionClass =
                "AD_HOC_FILE_SERVER_LISTENER",

            then="MEDIUM",
            else="HIGH"
        ) AS Severity,

        if(
            condition=DetectionClass =~
                '''^(NETCAT_OR_SOCAT|TUNNEL_TOOL|EXPLICIT_SHELL|INTERPRETER_SHELL)''',

            then="HIGH",
            else="MEDIUM"
        ) AS Confidence,

        if(
            condition=DetectionClass =~
                '''^NETCAT_OR_SOCAT_''',

            then="Netcat or Socat owns a listening or established network socket",

            else=if(
                condition=DetectionClass =~
                    '''^TUNNEL_TOOL_''',

                then="A dedicated tunneling or proxy utility owns a network socket",

                else=if(
                    condition=DetectionClass =~
                        '''^EXPLICIT_SHELL_''',

                    then="A shell owns a socket and contains explicit interactive or socket-redirection behavior",

                    else=if(
                        condition=DetectionClass =~
                            '''^INTERPRETER_SHELL_''',

                        then="An interpreter combines socket operations with shell-execution primitives",

                        else=if(
                            condition=DetectionClass =
                                "AD_HOC_FILE_SERVER_LISTENER",

                            then="An ad-hoc interpreter-based file server is listening for connections",
                            else="A temporary or deleted executable owns a network socket"
                        )
                    )
                )
            )
        ) AS Reason,

        if(
            condition=DetectionClass =~
                '''^TUNNEL_TOOL_''',

            then="T1572 - Supporting Network Context",

            else=if(
                condition=DetectionClass =~
                    '''^EXPLICIT_SHELL_''',

                then="T1059.004 - Supporting Process Context",

                else=if(
                    condition=DetectionClass =~
                        '''^INTERPRETER_SHELL_''',

                    then="T1059.006 - Supporting Process Context",

                    else=if(
                        condition=DetectionClass =
                            "AD_HOC_FILE_SERVER_LISTENER",

                        then="T1105 - Supporting Transfer Context",
                        else="UNASSIGNED_FROM_SOCKET_EVIDENCE"
                    )
                )
            )
        ) AS ATTACKContext,

        if(
            condition=DetectionClass =
                "NETCAT_OR_SOCAT_LISTENER",

            then=100,

            else=if(
                condition=DetectionClass =
                    "TUNNEL_TOOL_LISTENER",

                then=99,

                else=if(
                    condition=DetectionClass =
                        "EXPLICIT_SHELL_LISTENER",

                    then=98,

                    else=if(
                        condition=DetectionClass =
                            "INTERPRETER_SHELL_LISTENER",

                        then=97,

                        else=if(
                            condition=DetectionClass =
                                "NETCAT_OR_SOCAT_ESTABLISHED",

                            then=95,

                            else=if(
                                condition=DetectionClass =
                                    "TUNNEL_TOOL_ESTABLISHED",

                                then=94,

                                else=if(
                                    condition=DetectionClass =
                                        "EXPLICIT_SHELL_ESTABLISHED",

                                    then=93,

                                    else=if(
                                        condition=DetectionClass =
                                            "INTERPRETER_SHELL_ESTABLISHED",

                                        then=92,

                                        else=if(
                                            condition=DetectionClass =~
                                                '''^UNTRUSTED_PATH_''',

                                            then=90,
                                            else=85
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS DetectionPriority

    FROM NetworkClassified

    WHERE DetectionClass != "NOT_ACTIONABLE"


-- ============================================================
-- 5. Deduplicate network findings at process level
-- ============================================================

LET NetworkPrioritized <=
    SELECT *
    FROM NetworkScored
    ORDER BY DetectionPriority DESC


LET NetworkDeduplicated <=
    SELECT *
    FROM NetworkPrioritized
    GROUP BY NetworkFindingKey


LET NetworkFindings <=
    SELECT
        ClientId,
        Fqdn,

        Severity,
        Confidence,
        Finding,
        DetectionClass,

        "LTH.NetworkConnections/NetstatEnriched"
            AS EvidenceSource,

        format(
            format="%v (PID %v)",
            args=[
                ProcessName,
                Pid
            ]
        ) AS Subject,

        format(
            format="%v | %v:%v -> %v:%v | user=%v | command=%v",
            args=[
                ConnectionState,
                LocalAddress,
                LocalPort,
                RemoteAddress,
                RemotePort,
                Username,
                CommandLine
            ]
        ) AS Evidence,

        Reason,
        ATTACKContext,

        if(
            condition=DetectionClass =~ '''LISTENER$''',
            then="Suspicious Listening Services",
            else="Suspicious Network Tools or Shells"
        ) AS RiskScoreOwner,

        TRUE AS ReviewRequired,
        TRUE AS FindingGenerated,
        TRUE AS RiskScoreEligible,
        2 AS RiskWeight,

        format(
            format="NETWORK|%v",
            args=[NetworkFindingKey]
        ) AS FindingKey,

        "Direct" AS TelemetryCompatibility,
        "Needs Tuning" AS ReviewState,

        DetectionPriority AS SortPriority

    FROM NetworkDeduplicated


-- ============================================================
-- 6. Read DNS configuration evidence
-- ============================================================

LET DNSRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        format(
            format="%v",
            args=[Path]
        ) AS ConfigPath,

        format(
            format="%v",
            args=[Line]
        ) AS ConfigLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/DNSConfigReview"
    )


-- ============================================================
-- 7. Detect strong DNS configuration evidence
-- ============================================================

LET DNSSignals <=
    SELECT
        *,

        if(
            condition=ConfigLine =~
                '''^[[:space:]]*($|#|;)''',

            then=FALSE,
            else=TRUE
        ) AS ActiveLineEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)(^|[^a-z0-9_-])(iodine|dnscat2?|dns2tcp(c|d)?|heyoka|godoh|dns-exfil)([^a-z0-9_-]|$)''',

            then=TRUE,
            else=FALSE
        ) AS DNSTunnelToolEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)^[[:space:]]*(conf-file|resolv-file|addn-hosts|hostsdir|servers-file)[[:space:]]*=.*(/tmp/|/var/tmp/|/dev/shm/)''',

            then=TRUE,
            else=FALSE
        ) AS TemporaryConfigReferenceEvidence,

        format(
            format="%v|%v|%v",
            args=[
                ClientId,
                ConfigPath,
                ConfigLine
            ]
        ) AS DNSFindingKey

    FROM DNSRaw


LET DNSClassified <=
    SELECT
        *,

        if(
            condition=
                ActiveLineEvidence
                AND DNSTunnelToolEvidence,

            then="DNS_TUNNEL_TOOL_CONFIGURATION",

            else=if(
                condition=
                    ActiveLineEvidence
                    AND TemporaryConfigReferenceEvidence,

                then="TEMPORARY_DNS_CONFIG_REFERENCE",
                else="NOT_ACTIONABLE"
            )
        ) AS DetectionClass

    FROM DNSSignals


LET DNSFindingsRaw <=
    SELECT
        ClientId,
        Fqdn,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="HIGH",
            else="MEDIUM"
        ) AS Severity,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="HIGH",
            else="MEDIUM"
        ) AS Confidence,

        "Suspicious DNS Configuration" AS Finding,
        DetectionClass,

        "LTH.NetworkConnections/DNSConfigReview"
            AS EvidenceSource,

        ConfigPath AS Subject,
        ConfigLine AS Evidence,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="Active DNS configuration references a known DNS tunneling or exfiltration utility",
            else="Active DNS configuration references a file stored in a temporary directory"
        ) AS Reason,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="T1071.004 - Supporting Configuration Context",
            else="UNASSIGNED_FROM_CONFIGURATION_ONLY"
        ) AS ATTACKContext,

        "Suspicious DNS Configuration" AS RiskScoreOwner,

        TRUE AS ReviewRequired,
        TRUE AS FindingGenerated,
        TRUE AS RiskScoreEligible,
        2 AS RiskWeight,

        format(
            format="DNS|%v",
            args=[DNSFindingKey]
        ) AS FindingKey,

        "Supporting" AS TelemetryCompatibility,
        "Needs Tuning" AS ReviewState,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then=90,
            else=80
        ) AS SortPriority

    FROM DNSClassified

    WHERE DetectionClass != "NOT_ACTIONABLE"


LET DNSDeduplicated <=
    SELECT *
    FROM DNSFindingsRaw
    GROUP BY FindingKey


-- ============================================================
-- 8. Combine network and DNS findings
-- ============================================================

LET CombinedFindings <=
    SELECT *
    FROM chain(
        a=NetworkFindings,
        b=DNSDeduplicated
    )


LET CombinedPrioritized <=
    SELECT *
    FROM CombinedFindings
    ORDER BY SortPriority DESC


LET FinalDeduplicated <=
    SELECT *
    FROM CombinedPrioritized
    GROUP BY FindingKey


-- ============================================================
-- 9. Final output
-- ============================================================

SELECT
    ClientId,
    Fqdn,

    Severity,
    Confidence,

    Finding,
    DetectionClass,

    EvidenceSource,
    Subject,
    Evidence,

    Reason,
    ATTACKContext,

    RiskScoreOwner,
    ReviewRequired,
    FindingGenerated,
    RiskScoreEligible,
    RiskWeight,

    FindingKey,
    TelemetryCompatibility,
    ReviewState

FROM FinalDeduplicated

ORDER BY ClientId
```

## Cell 28 (markdown)

# Clients Needing Investigation — Deduplicated Network Summary

Summarizes unique actionable network and DNS findings per client. Findings are deduplicated at the process or configuration-line level. Ordinary SSH sessions, generic public connections, port-only indicators, public DNS resolvers, and policy-only DNS observations are excluded.

## Cell 29 (vql)

```vql
-- ============================================================
-- Clients Needing Investigation
-- Deduplicated Actionable Network Summary
--
-- Counting policy:
--   One network finding per unique process
--   One DNS finding per unique configuration line
--   Review-only and policy-only observations are excluded
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Read raw network socket and process evidence
-- ============================================================

LET NetworkRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        format(
            format="%v",
            args=[Status]
        ) AS ConnectionState,

        Pid,

        format(
            format="%v",
            args=[ProcInfo.Name]
        ) AS ProcessName,

        format(
            format="%v",
            args=[ProcInfo.Exe]
        ) AS ProcessPath,

        format(
            format="%v",
            args=[ProcInfo.CommandLine]
        ) AS CommandLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ '''(?i)^(LISTEN|ESTAB)'''


-- ============================================================
-- 2. Extract strong network indicators
-- ============================================================

LET NetworkSignals <=
    SELECT
        *,

        if(
            condition=ConnectionState =~ '''(?i)^LISTEN''',
            then=TRUE,
            else=FALSE
        ) AS ListenerEvidence,

        if(
            condition=ConnectionState =~ '''(?i)^ESTAB''',
            then=TRUE,
            else=FALSE
        ) AS EstablishedEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(nc|nc[.]openbsd|nc[.]traditional|ncat|netcat|socat|cryptcat)$'''

                OR ProcessPath =~
                    '''(?i)/(nc([.]openbsd|[.]traditional)?|ncat|netcat|socat|cryptcat)$''',

            then=TRUE,
            else=FALSE
        ) AS NetUtilityEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|sshuttle|cloudflared)$'''

                OR ProcessPath =~
                    '''(?i)/(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|sshuttle|cloudflared)$''',

            then=TRUE,
            else=FALSE
        ) AS TunnelToolEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(bash|sh|dash|zsh|ksh)$'''

                AND CommandLine =~
                    '''(?i)(/dev/(tcp|udp)/|[[:space:]]+-i([[:space:]]|$)|[0-9]?>&[0-9]|[0-9]?<&[0-9])''',

            then=TRUE,
            else=FALSE
        ) AS ExplicitShellChannelEvidence,

        if(
            condition=
                ProcessName =~
                    '''(?i)^(python([0-9.]+)?|perl|ruby)$'''

                AND CommandLine =~
                    '''(?i)(socket|TCPSocket|IO::Socket)'''

                AND CommandLine =~
                    '''(?i)(connect|create_connection|bind|listen)'''

                AND CommandLine =~
                    '''(?i)(subprocess|pty|dup2|exec|spawn|/bin/(bash|sh))''',

            then=TRUE,
            else=FALSE
        ) AS InterpreterShellEvidence,

        if(
            condition=
                (
                    ProcessName =~
                        '''(?i)^python([0-9.]+)?$'''

                    AND CommandLine =~
                        '''(?i)(^|[[:space:]])-m[[:space:]]+http[.]server([[:space:]]|$)'''
                )

                OR
                (
                    ProcessName =~ '''(?i)^php$'''

                    AND CommandLine =~
                        '''(?i)(^|[[:space:]])-S[[:space:]]+'''
                ),

            then=TRUE,
            else=FALSE
        ) AS AdHocFileServerEvidence,

        if(
            condition=ProcessPath =~
                '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)''',

            then=TRUE,
            else=FALSE
        ) AS TemporaryExecutableEvidence,

        if(
            condition=ProcessPath =~
                '''(?i)[(]deleted[)]$''',

            then=TRUE,
            else=FALSE
        ) AS DeletedExecutableEvidence,

        format(
            format="%v|%v|%v|%v|%v",
            args=[
                ClientId,
                Pid,
                ProcessName,
                ProcessPath,
                CommandLine
            ]
        ) AS NetworkFindingKey

    FROM NetworkRaw


-- ============================================================
-- 3. Classify actionable network behavior
-- ============================================================

LET NetworkClassified <=
    SELECT
        *,

        if(
            condition=
                ListenerEvidence
                AND NetUtilityEvidence,

            then="NETCAT_OR_SOCAT_LISTENER",

            else=if(
                condition=
                    ListenerEvidence
                    AND TunnelToolEvidence,

                then="TUNNEL_TOOL_LISTENER",

                else=if(
                    condition=
                        ListenerEvidence
                        AND ExplicitShellChannelEvidence,

                    then="EXPLICIT_SHELL_LISTENER",

                    else=if(
                        condition=
                            ListenerEvidence
                            AND InterpreterShellEvidence,

                        then="INTERPRETER_SHELL_LISTENER",

                        else=if(
                            condition=
                                ListenerEvidence
                                AND AdHocFileServerEvidence,

                            then="AD_HOC_FILE_SERVER_LISTENER",

                            else=if(
                                condition=
                                    ListenerEvidence
                                    AND
                                    (
                                        TemporaryExecutableEvidence
                                        OR DeletedExecutableEvidence
                                    ),

                                then="UNTRUSTED_PATH_LISTENER",

                                else=if(
                                    condition=
                                        EstablishedEvidence
                                        AND NetUtilityEvidence,

                                    then="NETCAT_OR_SOCAT_ESTABLISHED",

                                    else=if(
                                        condition=
                                            EstablishedEvidence
                                            AND TunnelToolEvidence,

                                        then="TUNNEL_TOOL_ESTABLISHED",

                                        else=if(
                                            condition=
                                                EstablishedEvidence
                                                AND ExplicitShellChannelEvidence,

                                            then="EXPLICIT_SHELL_ESTABLISHED",

                                            else=if(
                                                condition=
                                                    EstablishedEvidence
                                                    AND InterpreterShellEvidence,

                                                then="INTERPRETER_SHELL_ESTABLISHED",

                                                else=if(
                                                    condition=
                                                        EstablishedEvidence
                                                        AND
                                                        (
                                                            TemporaryExecutableEvidence
                                                            OR DeletedExecutableEvidence
                                                        ),

                                                    then="UNTRUSTED_PATH_ESTABLISHED",
                                                    else="NOT_ACTIONABLE"
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS DetectionClass

    FROM NetworkSignals


-- ============================================================
-- 4. Deduplicate network findings at process level
-- ============================================================

LET NetworkActionable <=
    SELECT
        ClientId,
        Fqdn,

        format(
            format="NETWORK|%v",
            args=[NetworkFindingKey]
        ) AS FindingKey,

        "NETWORK_PROCESS" AS FindingType

    FROM NetworkClassified

    WHERE DetectionClass != "NOT_ACTIONABLE"


LET NetworkDeduplicated <=
    SELECT *

    FROM NetworkActionable

    GROUP BY FindingKey


-- ============================================================
-- 5. Read DNS configuration evidence
-- ============================================================

LET DNSRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        format(
            format="%v",
            args=[Path]
        ) AS ConfigPath,

        format(
            format="%v",
            args=[Line]
        ) AS ConfigLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/DNSConfigReview"
    )


-- ============================================================
-- 6. Extract strong DNS configuration indicators
-- ============================================================

LET DNSSignals <=
    SELECT
        *,

        if(
            condition=ConfigLine =~
                '''^[[:space:]]*($|#|;)''',

            then=FALSE,
            else=TRUE
        ) AS ActiveLineEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)(^|[^a-z0-9_-])(iodine|dnscat2?|dns2tcp(c|d)?|heyoka|godoh|dns-exfil)([^a-z0-9_-]|$)''',

            then=TRUE,
            else=FALSE
        ) AS DNSTunnelToolEvidence,

        if(
            condition=ConfigLine =~
                '''(?i)^[[:space:]]*(conf-file|resolv-file|addn-hosts|hostsdir|servers-file)[[:space:]]*=.*(/tmp/|/var/tmp/|/dev/shm/)''',

            then=TRUE,
            else=FALSE
        ) AS TemporaryConfigReferenceEvidence,

        format(
            format="%v|%v|%v",
            args=[
                ClientId,
                ConfigPath,
                ConfigLine
            ]
        ) AS DNSFindingKey

    FROM DNSRaw


-- ============================================================
-- 7. Keep only actionable DNS evidence
-- ============================================================

LET DNSClassified <=
    SELECT
        *,

        if(
            condition=
                ActiveLineEvidence
                AND DNSTunnelToolEvidence,

            then="DNS_TUNNEL_TOOL_CONFIGURATION",

            else=if(
                condition=
                    ActiveLineEvidence
                    AND TemporaryConfigReferenceEvidence,

                then="TEMPORARY_DNS_CONFIG_REFERENCE",
                else="NOT_ACTIONABLE"
            )
        ) AS DetectionClass

    FROM DNSSignals


LET DNSActionable <=
    SELECT
        ClientId,
        Fqdn,

        format(
            format="DNS|%v",
            args=[DNSFindingKey]
        ) AS FindingKey,

        "DNS_CONFIGURATION" AS FindingType

    FROM DNSClassified

    WHERE DetectionClass != "NOT_ACTIONABLE"


LET DNSDeduplicated <=
    SELECT *

    FROM DNSActionable

    GROUP BY FindingKey


-- ============================================================
-- 8. Combine all actionable findings
-- ============================================================

LET CombinedFindings <=
    SELECT *

    FROM chain(
        a=NetworkDeduplicated,
        b=DNSDeduplicated
    )


-- Final safety deduplication

LET FinalDeduplicated <=
    SELECT *

    FROM CombinedFindings

    GROUP BY FindingKey


-- ============================================================
-- 9. Client-level investigation summary
-- ============================================================

SELECT
    ClientId,
    Fqdn,
    count() AS FindingCount

FROM FinalDeduplicated

GROUP BY ClientId

ORDER BY FindingCount DESC
```

## Cell 30 (markdown)

# Investigation Pivot Queue — Dynamic Network Evidence Routes

## Cell 31 (vql)

```vql
-- ============================================================
-- Investigation Pivot Queue
-- Dynamic Network Evidence Routes
--
-- Purpose:
--   Convert actionable network findings into investigation routes.
--
-- Important:
--   This cell does not generate additional Risk Score.
-- ============================================================

LET HuntId <= "HUNT_ID"


-- ============================================================
-- 1. Read network evidence
-- ============================================================

LET NetworkRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        format(format="%v", args=[Status])
            AS ConnectionState,

        format(format="%v", args=[Laddr])
            AS LocalAddress,

        format(format="%v", args=[Lport])
            AS LocalPort,

        format(format="%v", args=[Raddr])
            AS RemoteAddress,

        format(format="%v", args=[Rport])
            AS RemotePort,

        Pid,

        format(format="%v", args=[ProcInfo.Name])
            AS ProcessName,

        format(format="%v", args=[ProcInfo.Exe])
            AS ProcessPath,

        format(format="%v", args=[ProcInfo.Username])
            AS Username,

        format(format="%v", args=[ProcInfo.CommandLine])
            AS CommandLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/NetstatEnriched"
    )

    WHERE Status =~ '''(?i)^(LISTEN|ESTAB)'''


-- ============================================================
-- 2. Extract network indicators
-- ============================================================

LET NetworkSignals <=
    SELECT
        *,

        ConnectionState =~ '''(?i)^LISTEN'''
            AS ListenerEvidence,

        ConnectionState =~ '''(?i)^ESTAB'''
            AS EstablishedEvidence,

        (
            ProcessName =~
                '''(?i)^(nc|nc[.]openbsd|nc[.]traditional|ncat|netcat|socat|cryptcat)$'''

            OR ProcessPath =~
                '''(?i)/(nc([.]openbsd|[.]traditional)?|ncat|netcat|socat|cryptcat)$'''
        ) AS NetUtilityEvidence,

        (
            ProcessName =~
                '''(?i)^(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|sshuttle|cloudflared)$'''

            OR ProcessPath =~
                '''(?i)/(chisel|ngrok|frpc|frps|gost|ligolo-agent|ligolo-proxy|iodine|dnscat2|sshuttle|cloudflared)$'''
        ) AS TunnelToolEvidence,

        (
            ProcessName =~
                '''(?i)^(bash|sh|dash|zsh|ksh)$'''

            AND CommandLine =~
                '''(?i)(/dev/(tcp|udp)/|[[:space:]]+-i([[:space:]]|$)|[0-9]?>&[0-9]|[0-9]?<&[0-9])'''
        ) AS ExplicitShellEvidence,

        (
            ProcessName =~
                '''(?i)^(python([0-9.]+)?|perl|ruby)$'''

            AND CommandLine =~
                '''(?i)(socket|TCPSocket|IO::Socket)'''

            AND CommandLine =~
                '''(?i)(connect|create_connection|bind|listen)'''

            AND CommandLine =~
                '''(?i)(subprocess|pty|dup2|exec|spawn|/bin/(bash|sh))'''
        ) AS InterpreterShellEvidence,

        (
            (
                ProcessName =~ '''(?i)^python([0-9.]+)?$'''

                AND CommandLine =~
                    '''(?i)(^|[^a-z0-9])-m[^a-z0-9]+http[.]server([^a-z0-9.]|$)'''
            )

            OR

            (
                ProcessName =~ '''(?i)^php$'''

                AND CommandLine =~
                    '''(?i)(^|[^a-z0-9])-S([^a-z0-9]|$)'''
            )
        ) AS AdHocFileServerEvidence,

        ProcessPath =~
            '''(?i)^/(tmp|var/tmp|dev/shm)(/|$)'''
            AS TemporaryExecutableEvidence,

        ProcessPath =~
            '''(?i)[(]deleted[)]$'''
            AS DeletedExecutableEvidence,

        format(
            format="NETWORK|%v|%v|%v|%v|%v",
            args=[
                ClientId,
                Pid,
                ProcessName,
                ProcessPath,
                CommandLine
            ]
        ) AS FindingKey

    FROM NetworkRaw


-- ============================================================
-- 3. Classify actionable network evidence
-- ============================================================

LET NetworkClassified <=
    SELECT
        *,

        if(
            condition=
                ListenerEvidence AND ExplicitShellEvidence,

            then="EXPLICIT_SHELL_LISTENER",

            else=if(
                condition=
                    EstablishedEvidence AND ExplicitShellEvidence,

                then="EXPLICIT_SHELL_ESTABLISHED",

                else=if(
                    condition=
                        ListenerEvidence AND InterpreterShellEvidence,

                    then="INTERPRETER_SHELL_LISTENER",

                    else=if(
                        condition=
                            EstablishedEvidence
                            AND InterpreterShellEvidence,

                        then="INTERPRETER_SHELL_ESTABLISHED",

                        else=if(
                            condition=
                                ListenerEvidence AND TunnelToolEvidence,

                            then="TUNNEL_TOOL_LISTENER",

                            else=if(
                                condition=
                                    EstablishedEvidence
                                    AND TunnelToolEvidence,

                                then="TUNNEL_TOOL_ESTABLISHED",

                                else=if(
                                    condition=
                                        ListenerEvidence
                                        AND NetUtilityEvidence,

                                    then="NETCAT_OR_SOCAT_LISTENER",

                                    else=if(
                                        condition=
                                            EstablishedEvidence
                                            AND NetUtilityEvidence,

                                        then="NETCAT_OR_SOCAT_ESTABLISHED",

                                        else=if(
                                            condition=
                                                ListenerEvidence
                                                AND AdHocFileServerEvidence,

                                            then="AD_HOC_FILE_SERVER_LISTENER",

                                            else=if(
                                                condition=
                                                    ListenerEvidence
                                                    AND
                                                    (
                                                        TemporaryExecutableEvidence
                                                        OR DeletedExecutableEvidence
                                                    ),

                                                then="UNTRUSTED_PATH_LISTENER",

                                                else=if(
                                                    condition=
                                                        EstablishedEvidence
                                                        AND
                                                        (
                                                            TemporaryExecutableEvidence
                                                            OR DeletedExecutableEvidence
                                                        ),

                                                    then="UNTRUSTED_PATH_ESTABLISHED",
                                                    else="NOT_ACTIONABLE"
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
        ) AS DetectionClass

    FROM NetworkSignals


-- ============================================================
-- 4. Build network investigation routes
-- ============================================================

LET NetworkRoutesRaw <=
    SELECT
        ClientId,
        Fqdn,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL|INTERPRETER_SHELL)_''',

            then="CRITICAL",

            else=if(
                condition=DetectionClass =~
                    '''^(TUNNEL_TOOL|NETCAT_OR_SOCAT|UNTRUSTED_PATH)_''',

                then="HIGH",
                else="MEDIUM"
            )
        ) AS InvestigationPriority,

        DetectionClass,

        format(
            format="%v (PID %v)",
            args=[ProcessName, Pid]
        ) AS Subject,

        format(
            format="%v | %v:%v -> %v:%v | user=%v | path=%v | command=%v",
            args=[
                ConnectionState,
                LocalAddress,
                LocalPort,
                RemoteAddress,
                RemotePort,
                Username,
                ProcessPath,
                CommandLine
            ]
        ) AS Evidence,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL|INTERPRETER_SHELL)_''',

            then="Processes & Services",

            else=if(
                condition=DetectionClass =~
                    '''^TUNNEL_TOOL_''',

                then="Processes & Services",

                else=if(
                    condition=DetectionClass =~
                        '''^NETCAT_OR_SOCAT_''',

                    then="Processes & Services",

                    else=if(
                        condition=DetectionClass =
                            "AD_HOC_FILE_SERVER_LISTENER",

                        then="Data Access & Exfiltration",
                        else="Malware & Suspicious Tools"
                    )
                )
            )
        ) AS PrimaryPivot,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL|INTERPRETER_SHELL)_''',

            then="Authentication & SSH -> Persistence -> File Timeline -> Logs & Security Events",

            else=if(
                condition=DetectionClass =~
                    '''^TUNNEL_TOOL_''',

                then="Network Connections -> Persistence -> Authentication & SSH -> File Timeline",

                else=if(
                    condition=DetectionClass =~
                        '''^NETCAT_OR_SOCAT_''',

                    then="Network Connections -> Authentication & SSH -> Persistence -> File Timeline",

                    else=if(
                        condition=DetectionClass =
                            "AD_HOC_FILE_SERVER_LISTENER",

                        then="File Timeline -> Authentication & SSH -> Logs & Security Events",

                        else="File Timeline -> Processes & Services -> Persistence"
                    )
                )
            )
        ) AS PivotRoute,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL|INTERPRETER_SHELL)_''',

            then="Parent process, full command line, user, remote endpoint, shell history, sudo activity and persistence",

            else=if(
                condition=DetectionClass =~
                    '''^TUNNEL_TOOL_''',

                then="Tool configuration, relay address, forwarded ports, executable hash, owner and persistence",

                else=if(
                    condition=DetectionClass =~
                        '''^NETCAT_OR_SOCAT_''',

                    then="Parent process, command line, process user, remote endpoint, execution origin and persistence",

                    else=if(
                        condition=DetectionClass =
                            "AD_HOC_FILE_SERVER_LISTENER",

                        then="Working directory, exposed files, inbound clients, shell history and recent archives",

                        else="Executable hash, owner, timestamps, package ownership, YARA results and related files"
                    )
                )
            )
        ) AS RequiredEvidence,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL|INTERPRETER_SHELL)_''',

            then="Does the evidence confirm an interactive or reverse-shell channel?",

            else=if(
                condition=DetectionClass =~
                    '''^TUNNEL_TOOL_''',

                then="Is this tunnel approved and is its remote relay expected?",

                else=if(
                    condition=DetectionClass =~
                        '''^NETCAT_OR_SOCAT_''',

                    then="Is this utility authorized, and was it used for shell access or file transfer?",

                    else=if(
                        condition=DetectionClass =
                            "AD_HOC_FILE_SERVER_LISTENER",

                        then="What directory was exposed and did it contain sensitive or staged data?",

                        else="Is the temporary or deleted executable trusted and present on other clients?"
                    )
                )
            )
        ) AS AnalystQuestion,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL|INTERPRETER_SHELL)_''',

            then="Shell execution, unknown remote endpoint, elevated privileges or related persistence",

            else=if(
                condition=DetectionClass =~
                    '''^TUNNEL_TOOL_''',

                then="Unapproved relay, unknown owner, root execution or persistent deployment",

                else=if(
                    condition=DetectionClass =~
                        '''^NETCAT_OR_SOCAT_''',

                    then="Shell redirection, unknown remote endpoint, root execution or persistence",

                    else=if(
                        condition=DetectionClass =
                            "AD_HOC_FILE_SERVER_LISTENER",

                        then="Sensitive files exposed, listener on all interfaces or unknown inbound client",

                        else="Unknown hash, executable deletion, suspicious parent or fleet-wide presence"
                    )
                )
            )
        ) AS EscalateWhen,

        if(
            condition=DetectionClass =~
                '''^(EXPLICIT_SHELL|INTERPRETER_SHELL)_''',

            then=100,

            else=if(
                condition=DetectionClass =~
                    '''^TUNNEL_TOOL_''',

                then=95,

                else=if(
                    condition=DetectionClass =~
                        '''^NETCAT_OR_SOCAT_''',

                    then=90,

                    else=if(
                        condition=DetectionClass =~
                            '''^UNTRUSTED_PATH_''',

                        then=85,
                        else=70
                    )
                )
            )
        ) AS RouteRank,

        FindingKey,

        "NONE - routing only" AS RiskScoreImpact,
        "Open" AS InvestigationState

    FROM NetworkClassified

    WHERE DetectionClass != "NOT_ACTIONABLE"


LET NetworkPrioritized <=
    SELECT *
    FROM NetworkRoutesRaw
    ORDER BY RouteRank DESC


LET NetworkRoutes <=
    SELECT *
    FROM NetworkPrioritized
    GROUP BY FindingKey


-- ============================================================
-- 5. Read and classify DNS evidence
-- ============================================================

LET DNSRaw <=
    SELECT
        ClientId,

        client_info(
            client_id=ClientId
        ).os_info.fqdn AS Fqdn,

        format(format="%v", args=[Path])
            AS ConfigPath,

        format(format="%v", args=[Line])
            AS ConfigLine

    FROM hunt_results(
        hunt_id=HuntId,
        artifact="LTH.NetworkConnections/DNSConfigReview"
    )


LET DNSSignals <=
    SELECT
        *,

        NOT ConfigLine =~
            '''^[[:space:]]*($|#|;)'''
            AS ActiveLineEvidence,

        ConfigLine =~
            '''(?i)(^|[^a-z0-9_-])(iodine|dnscat2?|dns2tcp(c|d)?|heyoka|godoh|dns-exfil)([^a-z0-9_-]|$)'''
            AS DNSTunnelToolEvidence,

        ConfigLine =~
            '''(?i)^[[:space:]]*(conf-file|resolv-file|addn-hosts|hostsdir|servers-file)[[:space:]]*=.*(/tmp/|/var/tmp/|/dev/shm/)'''
            AS TemporaryConfigEvidence,

        format(
            format="DNS|%v|%v|%v",
            args=[
                ClientId,
                ConfigPath,
                ConfigLine
            ]
        ) AS FindingKey

    FROM DNSRaw


LET DNSClassified <=
    SELECT
        *,

        if(
            condition=
                ActiveLineEvidence
                AND DNSTunnelToolEvidence,

            then="DNS_TUNNEL_TOOL_CONFIGURATION",

            else=if(
                condition=
                    ActiveLineEvidence
                    AND TemporaryConfigEvidence,

                then="TEMPORARY_DNS_CONFIG_REFERENCE",
                else="NOT_ACTIONABLE"
            )
        ) AS DetectionClass

    FROM DNSSignals


LET DNSRoutesRaw <=
    SELECT
        ClientId,
        Fqdn,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="HIGH",
            else="MEDIUM"
        ) AS InvestigationPriority,

        DetectionClass,
        ConfigPath AS Subject,
        ConfigLine AS Evidence,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="Logs & Security Events",
            else="File Timeline"
        ) AS PrimaryPivot,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="Malware & Suspicious Tools -> Processes & Services -> Persistence -> Network Connections",

            else="Logs & Security Events -> Processes & Services -> Persistence"
        ) AS PivotRoute,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="Related process, configuration timestamps, queried domains, DNS frequency, service and executable hash",

            else="Referenced file, owner, permissions, timestamps, modifying process and active service"
        ) AS RequiredEvidence,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="Is the referenced tunneling utility executing or generating suspicious DNS traffic?",

            else="Why does active DNS configuration reference a temporary file?"
        ) AS AnalystQuestion,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then="Confirmed execution, suspicious DNS queries, unknown domains or persistence",

            else="Unknown owner, unauthorized modification, suspicious process or recreation through persistence"
        ) AS EscalateWhen,

        if(
            condition=DetectionClass =
                "DNS_TUNNEL_TOOL_CONFIGURATION",

            then=80,
            else=60
        ) AS RouteRank,

        FindingKey,

        "NONE - routing only" AS RiskScoreImpact,
        "Open" AS InvestigationState

    FROM DNSClassified

    WHERE DetectionClass != "NOT_ACTIONABLE"


LET DNSRoutes <=
    SELECT *
    FROM DNSRoutesRaw
    GROUP BY FindingKey


-- ============================================================
-- 6. Combine and deduplicate all routes
-- ============================================================

LET AllRoutes <=
    SELECT *
    FROM chain(
        a=NetworkRoutes,
        b=DNSRoutes
    )


LET RoutesPrioritized <=
    SELECT *
    FROM AllRoutes
    ORDER BY RouteRank DESC


LET FinalRoutes <=
    SELECT *
    FROM RoutesPrioritized
    GROUP BY FindingKey


-- ============================================================
-- 7. Final analyst-facing pivot queue
-- ============================================================

SELECT
    ClientId,
    Fqdn,

    InvestigationPriority,
    DetectionClass,

    Subject,
    Evidence,

    PrimaryPivot,
    PivotRoute,
    RequiredEvidence,

    AnalystQuestion,
    EscalateWhen,

    InvestigationState,
    FindingKey,
    RiskScoreImpact

FROM FinalRoutes

ORDER BY RouteRank DESC
```

## Cell 32 (markdown)

# Investigation Pivot Guide — Network Evidence Routes

## Cell 33 (vql)

```vql
-- ============================================================
-- Investigation Pivot Guide
-- Network Evidence Routes
--
-- Purpose:
--   Provide a fixed investigation route catalog for every
--   actionable Network DetectionClass.
--
-- Important:
--   - This cell does not create findings.
--   - This cell does not contribute to Risk Score.
--   - Use the Dynamic Pivot Queue to identify the actual client.
-- ============================================================


LET NetworkPivotGuide <=
    SELECT
        RouteOrder,
        DetectionClasses,
        DefaultPriority,
        PrimaryPivot,
        NextNotebook,
        InvestigationObjective,
        RequiredEvidence,
        EscalateWhen,

        "NONE - guide only" AS RiskScoreImpact

    FROM foreach(
        row=[

            -- ====================================================
            -- Route 1: Explicit shell channel
            -- ====================================================

            dict(
                RouteOrder=1,

                DetectionClasses=
                    "EXPLICIT_SHELL_LISTENER | EXPLICIT_SHELL_ESTABLISHED",

                DefaultPriority="CRITICAL",

                PrimaryPivot="Processes & Services",

                NextNotebook=
                    "LTH - 04 - Processes & Services Dashboard",

                InvestigationObjective=
                    "Confirm whether the socket belongs to an interactive shell, reverse shell or unauthorized command channel.",

                RequiredEvidence=
                    "Full command line; parent and grandparent processes; process user and privileges; local and remote endpoints; authentication events; shell and sudo history; related files; persistence evidence.",

                EscalateWhen=
                    "Explicit shell redirection or interactive-shell arguments are present; the remote endpoint is unknown; the process runs with elevated privileges; or related persistence is identified."
            ),


            -- ====================================================
            -- Route 2: Interpreter-based shell
            -- ====================================================

            dict(
                RouteOrder=2,

                DetectionClasses=
                    "INTERPRETER_SHELL_LISTENER | INTERPRETER_SHELL_ESTABLISHED",

                DefaultPriority="CRITICAL",

                PrimaryPivot="Processes & Services",

                NextNotebook=
                    "LTH - 04 - Processes & Services Dashboard",

                InvestigationObjective=
                    "Determine whether Python, Perl or Ruby code is creating a socket and spawning or controlling a shell.",

                RequiredEvidence=
                    "Interpreter command line; inline code or script path; parent process; initiating user; socket operations; shell-spawning functions; remote endpoint; script hash; file timestamps; related modules and persistence.",

                EscalateWhen=
                    "The code combines socket activity with subprocess, pty, dup2, exec, spawn or /bin/sh behavior; connects to an unknown remote endpoint; runs as root; or is deployed through persistence."
            ),


            -- ====================================================
            -- Route 3: Tunneling or proxy tool
            -- ====================================================

            dict(
                RouteOrder=3,

                DetectionClasses=
                    "TUNNEL_TOOL_LISTENER | TUNNEL_TOOL_ESTABLISHED",

                DefaultPriority="HIGH",

                PrimaryPivot="Processes & Services",

                NextNotebook=
                    "LTH - 04 - Processes & Services Dashboard",

                InvestigationObjective=
                    "Determine whether the process created an authorized tunnel or an unauthorized proxy, relay or covert access path.",

                RequiredEvidence=
                    "Complete command line; configuration file; client or server mode; relay address; listening and forwarded ports; authentication tokens or certificates; executable path and hash; process owner; systemd or cron persistence.",

                EscalateWhen=
                    "The relay is not approved; the owner or deployment purpose is unknown; the process runs as root; the executable is located outside an approved path; or persistent deployment is present."
            ),


            -- ====================================================
            -- Route 4: Netcat or Socat activity
            -- ====================================================

            dict(
                RouteOrder=4,

                DetectionClasses=
                    "NETCAT_OR_SOCAT_LISTENER | NETCAT_OR_SOCAT_ESTABLISHED",

                DefaultPriority="HIGH",

                PrimaryPivot="Processes & Services",

                NextNotebook=
                    "LTH - 04 - Processes & Services Dashboard",

                InvestigationObjective=
                    "Distinguish authorized administrative use from shell access, port forwarding or unauthorized file transfer.",

                RequiredEvidence=
                    "Complete command line; parent process; process username; effective privileges; local and remote endpoints; execution origin; SSH and sudo activity; transferred files; systemd, cron or shell-profile persistence.",

                EscalateWhen=
                    "Shell execution or redirection is present; the remote endpoint is unknown; the process runs as root; the executable runs from a temporary location; or related persistence or data staging is identified."
            ),


            -- ====================================================
            -- Route 5: Temporary or deleted executable
            -- ====================================================

            dict(
                RouteOrder=5,

                DetectionClasses=
                    "UNTRUSTED_PATH_LISTENER | UNTRUSTED_PATH_ESTABLISHED",

                DefaultPriority="HIGH",

                PrimaryPivot="Malware & Suspicious Tools",

                NextNotebook=
                    "LTH - 11 - Malware & Suspicious Tools Dashboard",

                InvestigationObjective=
                    "Preserve and analyze the temporary, non-standard or deleted executable responsible for network activity.",

                RequiredEvidence=
                    "SHA256 hash; file size; owner; permissions; timestamps; package ownership; parent process; command line; open files; related files in the same directory; YARA results; executable sample when collection is permitted.",

                EscalateWhen=
                    "The hash or file origin is unknown; the executable was deleted after execution; it has a suspicious parent process; runs with elevated privileges; or the same hash is present on other clients."
            ),


            -- ====================================================
            -- Route 6: Ad-hoc file server
            -- ====================================================

            dict(
                RouteOrder=6,

                DetectionClasses=
                    "AD_HOC_FILE_SERVER_LISTENER",

                DefaultPriority="MEDIUM",

                PrimaryPivot="Data Access & Exfiltration",

                NextNotebook=
                    "LTH - 13 - Data Access & Exfiltration Dashboard",

                InvestigationObjective=
                    "Identify the directory and data exposed by the temporary web server and determine whether files were staged or transferred.",

                RequiredEvidence=
                    "Process working directory; listening interface; served files; recent archives; credential files; database dumps; inbound client addresses; shell history; process owner; file access and transfer evidence.",

                EscalateWhen=
                    "Sensitive or staged files were exposed; the server listened on all interfaces; an unknown remote client connected; or archive and data-staging activity occurred before the listener started."
            ),


            -- ====================================================
            -- Route 7: DNS tunneling configuration
            -- ====================================================

            dict(
                RouteOrder=7,

                DetectionClasses=
                    "DNS_TUNNEL_TOOL_CONFIGURATION",

                DefaultPriority="HIGH",

                PrimaryPivot="Logs & Security Events",

                NextNotebook=
                    "LTH - 08 - Logs & Security Events Dashboard",

                InvestigationObjective=
                    "Confirm whether the referenced DNS tunneling utility is executing or generating suspicious DNS traffic.",

                RequiredEvidence=
                    "Related processes; service and cron entries; configuration timestamps and owner; queried domains; query frequency; unusually long or encoded subdomains; authoritative DNS infrastructure; executable path and hash.",

                EscalateWhen=
                    "Tool execution is confirmed; suspicious DNS queries are observed; unknown domains or authoritative DNS servers are used; or the tool is maintained through persistence."
            ),


            -- ====================================================
            -- Route 8: Temporary DNS configuration reference
            -- ====================================================

            dict(
                RouteOrder=8,

                DetectionClasses=
                    "TEMPORARY_DNS_CONFIG_REFERENCE",

                DefaultPriority="MEDIUM",

                PrimaryPivot="File Timeline",

                NextNotebook=
                    "LTH - 07 - File Timeline Dashboard",

                InvestigationObjective=
                    "Determine why active DNS configuration references a file in a temporary directory and identify who created or modified it.",

                RequiredEvidence=
                    "Referenced-file existence; owner; permissions; timestamps; file content; parent-configuration metadata; modifying process or user; related service; DNS behavior changes; persistence that recreates the file.",

                EscalateWhen=
                    "The file owner is unknown; the change was unauthorized; a suspicious process consumes the configuration; DNS behavior changed after modification; or persistence recreates the temporary file."
            )

        ],

        query={
            SELECT
                RouteOrder,
                DetectionClasses,
                DefaultPriority,
                PrimaryPivot,
                NextNotebook,
                InvestigationObjective,
                RequiredEvidence,
                EscalateWhen

            FROM scope()
        }
    )


SELECT
    RouteOrder,
    DetectionClasses,
    DefaultPriority,
    PrimaryPivot,
    NextNotebook,
    InvestigationObjective,
    RequiredEvidence,
    EscalateWhen,
    RiskScoreImpact

FROM NetworkPivotGuide

ORDER BY RouteOrder
```
