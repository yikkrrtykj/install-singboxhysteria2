#!/usr/bin/env bash
# Phase D helpers: sing-box 1.14.x stable selection and localhost-only API config.
#
# This file is deliberately side-effect free when sourced. Production upgrade,
# restart and rollback integration is added separately after these primitives are
# regression-tested.

PHASE_D_TARGET_MAJOR="${PHASE_D_TARGET_MAJOR:-1}"
PHASE_D_TARGET_MINOR="${PHASE_D_TARGET_MINOR:-14}"
PHASE_D_MIN_VERSION="${PHASE_D_MIN_VERSION:-1.14.0}"
PHASE_D_FALLBACK_TAG="${PHASE_D_FALLBACK_TAG:-v1.14.0}"
PHASE_D_API_TAG="${PHASE_D_API_TAG:-monitor-api}"
PHASE_D_API_LISTEN="${PHASE_D_API_LISTEN:-127.0.0.1}"
PHASE_D_API_PORT="${PHASE_D_API_PORT:-9091}"

phase_d_warn() {
    if declare -F warning >/dev/null 2>&1; then
        warning "$*"
    else
        printf '%s\n' "$*" >&2
    fi
}

phase_d_info() {
    if declare -F info >/dev/null 2>&1; then
        info "$*"
    else
        printf '%s\n' "$*"
    fi
}

phase_d_version_in_target_series() { # <version-or-tag>
    local version="${1#v}"
    [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || return 1
    [ "${BASH_REMATCH[1]}" = "$PHASE_D_TARGET_MAJOR" ] || return 1
    [ "${BASH_REMATCH[2]}" = "$PHASE_D_TARGET_MINOR" ] || return 1
    return 0
}

phase_d_version_at_least_min() { # <version-or-tag>
    local version="${1#v}" minimum="${PHASE_D_MIN_VERSION#v}"
    local v_major v_minor v_patch m_major m_minor m_patch
    [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    [[ "$minimum" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS='.' read -r v_major v_minor v_patch <<< "$version"
    IFS='.' read -r m_major m_minor m_patch <<< "$minimum"
    (( 10#$v_major > 10#$m_major )) && return 0
    (( 10#$v_major < 10#$m_major )) && return 1
    (( 10#$v_minor > 10#$m_minor )) && return 0
    (( 10#$v_minor < 10#$m_minor )) && return 1
    (( 10#$v_patch >= 10#$m_patch ))
}

phase_d_release_tag_is_allowed() { # <tag>
    local tag="$1"
    [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    phase_d_version_in_target_series "$tag" || return 1
    phase_d_version_at_least_min "$tag"
}

phase_d_select_release_from_json() {
    # Reads the GitHub releases JSON array on stdin and prints the newest stable
    # v1.14.x tag. Pre-releases/drafts and future major/minor series are ignored.
    local selected
    selected="$(jq -er \
        --argjson major "$PHASE_D_TARGET_MAJOR" \
        --argjson minor "$PHASE_D_TARGET_MINOR" '
          [ .[]
            | select((.draft // false) == false)
            | select((.prerelease // false) == false)
            | .tag_name as $tag
            | select($tag | type == "string")
            | ($tag | capture("^v(?<major>[0-9]+)\\.(?<minor>[0-9]+)\\.(?<patch>[0-9]+)$")?) as $v
            | select($v != null)
            | select(($v.major | tonumber) == $major and ($v.minor | tonumber) == $minor)
            | {
                tag: $tag,
                major: ($v.major | tonumber),
                minor: ($v.minor | tonumber),
                patch: ($v.patch | tonumber)
              }
          ]
          | sort_by([.major, .minor, .patch])
          | last
          | .tag
        ' 2>/dev/null)" || return 1
    phase_d_release_tag_is_allowed "$selected" || return 1
    printf '%s\n' "$selected"
}

phase_d_config_structure_problems() { # <config>
    local cfg="$1"
    jq -r \
      --arg tag "$PHASE_D_API_TAG" \
      --arg listen "$PHASE_D_API_LISTEN" \
      --argjson port "$PHASE_D_API_PORT" '
      if type != "object" then
        ["配置根节点不是 object"]
      elif (has("services") and ((.services | type) != "array")) then
        ["services 存在但不是数组"]
      else
        ((.services // []) | map(select(.tag == $tag))) as $m |
        ([ ]
          + (if ($m | length) > 1 then ["monitor-api service 数量大于 1"] else [] end)
          + (if ($m | length) == 1 and ($m[0].type // "") != "api"
             then ["monitor-api type 不是 api"] else [] end)
          + (if ($m | length) == 1 and ($m[0].listen // "") != $listen
             then ["monitor-api listen 不是 127.0.0.1"] else [] end)
          + (if ($m | length) == 1 and ($m[0].listen_port // -1) != $port
             then ["monitor-api listen_port 不是 9091"] else [] end)
        )
      end
      | .[]
    ' "$cfg" 2>/dev/null
}

phase_d_identity_problems() { # <config>
    # Upgrade requires Phase C identity migration to have happened explicitly.
    # This check is intentionally fail-closed and does not mutate credentials.
    local cfg="$1"
    jq -r '
      if type != "object" then
        ["配置根节点不是 object"]
      elif ((.inbounds // null) | type) != "array" then
        ["缺少或非法 inbounds"]
      else
        ([.inbounds[] | select(.tag == "vless-in")]) as $ri |
        ([.inbounds[] | select(.tag == "hy2-in")]) as $hi |
        if ($ri | length) != 1 then
          ["vless-in 入站数量不是 1"]
        elif ($hi | length) != 1 then
          ["hy2-in 入站数量不是 1"]
        elif (($ri[0].users // null) | type) != "array" then
          ["vless-in users 缺失或不是数组"]
        elif (($hi[0].users // null) | type) != "array" then
          ["hy2-in users 缺失或不是数组"]
        else
          ($ri[0].users) as $ru |
          ($hi[0].users) as $hu |
          ([ $ru[] | (.name // "") ]) as $rn |
          ([ $hu[] | (.name // "") ]) as $hn |
          ([ ]
            + (if ($rn | index("")) != null then ["vless-in 存在未命名用户，请先执行 legacy 迁移"] else [] end)
            + (if ($hn | index("")) != null then ["hy2-in 存在未命名用户，请先执行 legacy 迁移"] else [] end)
            + (if ($rn | sort) == ($hn | sort) then [] else ["Reality 与 HY2 的 name 集合不一致"] end)
            + (if ($rn | length) == ($rn | unique | length) then [] else ["vless-in 存在重复 name"] end)
            + (if ($hn | length) == ($hn | unique | length) then [] else ["hy2-in 存在重复 name"] end)
          )
        end
      end
      | .[]
    ' "$cfg" 2>/dev/null
}

phase_d_collect_problems() { # <config>
    local cfg="$1" out rc
    out="$(phase_d_config_structure_problems "$cfg")"; rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    [ -n "$out" ] && printf '%s\n' "$out"
    out="$(phase_d_identity_problems "$cfg")"; rc=$?
    [ "$rc" -eq 0 ] || return "$rc"
    [ -n "$out" ] && printf '%s\n' "$out"
}

phase_d_config_ready() { # <config>
    local problems rc
    problems="$(phase_d_collect_problems "$1")"; rc=$?
    if [ "$rc" -ne 0 ]; then
        phase_d_warn "Phase D 配置审计执行失败"
        return 1
    fi
    if [ -n "$problems" ]; then
        printf '%s\n' "$problems" >&2
        return 1
    fi
    return 0
}

phase_d_inject_api_service() { # <input> <output>
    local input="$1" output="$2" problems rc count tmp
    problems="$(phase_d_config_structure_problems "$input")"; rc=$?
    if [ "$rc" -ne 0 ]; then
        phase_d_warn "Phase D API 结构审计执行失败"
        return 1
    fi
    if [ -n "$problems" ]; then
        printf '%s\n' "$problems" >&2
        return 1
    fi

    count="$(jq -er --arg tag "$PHASE_D_API_TAG" '[(.services // [])[] | select(.tag == $tag)] | length' "$input" 2>/dev/null)" || return 1
    if [ "$count" -eq 1 ]; then
        # Existing exact service passed the structural audit; preserve config.
        cp -a -- "$input" "$output" || return 1
        return 0
    fi

    tmp="${output}.tmp.$$"
    rm -f -- "$tmp"
    if ! jq \
      --arg tag "$PHASE_D_API_TAG" \
      --arg listen "$PHASE_D_API_LISTEN" \
      --argjson port "$PHASE_D_API_PORT" '
        .services = ((.services // []) + [{
          "type": "api",
          "tag": $tag,
          "listen": $listen,
          "listen_port": $port
        }])
      ' "$input" > "$tmp"; then
        rm -f -- "$tmp"
        return 1
    fi
    mv -f -- "$tmp" "$output" || { rm -f -- "$tmp"; return 1; }

    problems="$(phase_d_config_structure_problems "$output")"; rc=$?
    if [ "$rc" -ne 0 ] || [ -n "$problems" ]; then
        rm -f -- "$output"
        [ -n "$problems" ] && printf '%s\n' "$problems" >&2
        return 1
    fi
    return 0
}

phase_d_api_service_exact() { # <config>
    local cfg="$1"
    jq -e \
      --arg tag "$PHASE_D_API_TAG" \
      --arg listen "$PHASE_D_API_LISTEN" \
      --argjson port "$PHASE_D_API_PORT" '
        [(.services // [])[] | select(.tag == $tag)] as $m |
        ($m | length) == 1 and
        $m[0].type == "api" and
        $m[0].listen == $listen and
        $m[0].listen_port == $port
      ' "$cfg" >/dev/null 2>&1
}
