<?php
/*
Install by copying this file to /usr/local/pkg/. It will automatically be picked up by filter reloads.
*/
function custom_pf_generate_rules($ruletype) {
    global $config;

    $proxy_port = 19800;
    $rules = "";

    log_error("custom reflections");
    if ($ruletype == "nat") {
        // Open inetd.conf write handle
        $inetd_fd = fopen("/var/etc/inetd.conf","a");

        foreach ($config['nat']['rule'] as $rule) {
            if (isset($rule['disabled']))
                continue;
                
            if (strpos($rule['destination']['port'], "-") !== FALSE) {
                log_error("Skipping NAT rule with a port range");
                continue;   
            }

            if ($rule['interface'] == 'opt1' && $rule['destination']['network'] == 'opt1ip') {
                switch($rule['protocol']) {
                    case "tcp/udp":
                        $protocol = "{ tcp udp }";
                        $reflect_protos = array('tcp', 'udp');
                        break;
                    case "tcp":
                    case "udp":
                        $protocol = $rule['protocol'];
                        $reflect_protos = array($rule['protocol']);
                        break;
                    default:
                        return "";
                        break;
                }
                foreach ($reflect_protos as $proto) {
                    $rules .= generate_nat($rule, $proto, $proxy_port);
                    append_inetd($rule, $proto, $proxy_port, $inetd_fd);
                }
                $proxy_port++;
            }

            log_error(json_encode($rule));
        }

        fclose($inetd_fd);
        return $rules;
    } else {
        return "";
    }
}

function generate_nat($rule, $proto, $proxy_port) {
    return "rdr on re0 proto {$proto} " .
        "from any to 195.165.181.3 port {$rule['destination']['port']} " .
        "tag PFREFLECT -> 127.0.0.1 port {$proxy_port}\n";
}

function append_inetd($rule, $proto, $proxy_port, $inetd_fd) {
    global $config, $FilterIflist;

    if ($config['system']['reflectiontimeout'])
        $reflectiontimeout = $config['system']['reflectiontimeout'];
    else
        $reflectiontimeout = "2000";

    if ($proto == "udp") {
        $socktype = "dgram";
        $dash_u = "-u ";
        $wait = "wait\t";
    } else {
        $socktype = "stream";
        $dash_u = "";
        $wait = "nowait/0";
    }

    if (is_alias($rule['target']))
        $target = filter_expand_alias($rule['target']);
    else if(is_ipaddr($rule['target']))
        $target = $rule['target'];
    else if (is_ipaddr($FilterIflist[$rule['target']]['ip']))
        $target = $FilterIflist[$rule['target']]['ip'];
    else
        return "";

    foreach (explode(" ", trim($target)) as $targip) {
        if (empty($targip))
            continue;
        fwrite($inetd_fd, "{$proxy_port}\t{$socktype}\t{$proto}\t{$wait}\tnobody\t/usr/bin/nc\tnc {$dash_u}-w {$reflectiontimeout} {$targip} {$rule['local-port']}\n");
    }
}
