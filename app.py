#!tapi_env/bin/python

"""
Rest with Flask:
    http://blog.miguelgrinberg.com/post/designing-a-restful-api-with-python-and-flask
    http://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world
Iptables
    https://github.com/ldx/python-iptables
    https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg
    http://www.iptables.info/en/structure-of-iptables.html
    http://www.iptables.info/files/tables_traverse.jpg
    http://www.thegeekstuff.com/2011/06/iptables-rules-examples/

Test the stuff on:
    http://127.0.0.1:5000/firewall/api/v1.0/rules/
"""
__author__ = 'tamas'
from flask import Flask, jsonify, url_for, abort, request
import iptc
import re
import subprocess

app = Flask(__name__)


def has_no_empty_params(rule):
    defaults = rule.defaults if rule.defaults is not None else ()
    arguments = rule.arguments if rule.arguments is not None else ()
    return len(defaults) >= len(arguments)


@app.route('/')
def index():
    links = []
    for rule in app.url_map.iter_rules():
        print rule
        # Filter out rules we can't navigate to in a browser
        # and rules that require parameters
        if "GET" in rule.methods and has_no_empty_params(rule):
            url = url_for(rule.endpoint, **(rule.defaults or {}))
            links.append((url, rule.endpoint))
            # links is now a list of url, endpoint tuples
    return jsonify({"routes": links})


@app.route('/firewall/api/v1.0/flush/', methods=['GET'])
def flush():
    table = iptc.Table(iptc.Table.FILTER)
    for chain in table.chains:
        table.flush_entries(chain)
    return "OK"


@app.route('/firewall/api/v1.0/rules/', defaults={'chain_name': None}, methods=['GET'])
@app.route('/firewall/api/v1.0/rules/<string:chain_name>', methods=['GET'])
def get_fw_status(chain_name):
    """
    Return the current rule-set of channels
    :type chain_name: string
    :return: the list of chains
    """
    chains = []
    if not chain_name:
        table = iptc.Table(iptc.Table.FILTER)
        for chain in table.chains:
            chains.append({'id': chain.name, 'rules': extract_rules(chain)})
    else:
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
        chains.append({'id': chain.name, 'rules': extract_rules(chain)})
    return jsonify({'rules': chains})


def extract_rules(chain):
    rules = []
    for rule in chain.rules:
        matches = []
        for match in rule.matches:
            matches.append({"comment": match.comment, "name": match.name})
        rules.append(
            {"target": rule.target.name, "in_iface": rule.in_interface, "proto": rule.protocol, "src": rule.src,
             "dst": rule.dst,
             "out_iface": rule.out_interface, "matches": matches})
    return rules


@app.route('/firewall/api/v1.0/rules/<string:chain_name>', methods=['PUT'])
def add_rule(chain_name):
    if not chain_name:
        abort(400)
    if not request.json:
        abort(400)

    rule = iptc.Rule()
    src = request.json.get('src')
    if src:
        rule.src = src

    dst = request.json.get('dst')
    if dst:
        rule.dst = dst

    proto = request.json.get('proto')
    if proto:
        rule.protocol = proto

    target = request.json.get('target')
    if target:
        rule.target = rule.create_target(target)

    in_iface = request.json.get('in_iface')
    if in_iface:
        rule.in_interface = in_iface

    out_iface = request.json.get('out_iface')
    if out_iface:
        rule.out_interface = out_iface

    dport = request.json.get('dport')
    if dport:
        match = rule.create_match(proto if proto else 'tcp')
        match.dport = dport

    sport = request.json.get('sport')
    if sport:
        match = rule.create_match(proto if proto else 'tcp')
        match.sport = sport

    matches = request.json.get('matches')
    if matches:
        print matches
        for this_match in matches:
            match = rule.create_match(this_match['name'])
            match.comment = this_match['comment']
    try:
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), chain_name)
        chain.insert_rule(rule)
        return jsonify(
            {'status': 'OK', 'proto': rule.protocol, 'target': rule.target.name, 'src': rule.src, 'dst': rule.dst,
             'in': rule.in_interface, 'out': rule.out_interface})
    except ValueError as e:
        abort(406)


# 'matches': [m.name: m for m in rule.matches]
# ,'mask': rule.mask
# 'fragment': rule.fragment
@app.route('/files/api/v1.0/grep', methods=['PUT'])
def scan_file():
    exp = request.json.get('e')
    file_path = request.json.get('p')
    if exp and file_path:
        lines = []
        with open(file_path) as file:
            for line in file:
                if re.search(exp, line):
                    lines.append({'match': line})

            return jsonify({"lines": lines})
    else:
        abort(400)


@app.route('/os/api/v1.0/exec', methods=['PUT'])
def execute_command():
    cmd = request.json.get('cmd')
    if not cmd:
        abort(400)
    out = subprocess.check_output(cmd, shell=True)
    return jsonify({'out': out})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=80)
