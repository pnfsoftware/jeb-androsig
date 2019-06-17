/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.stream.Collectors;

import com.pnf.androsig.apply.model.MethodSignature;
import com.pnfsoftware.jeb.util.collect.CollectionUtil;
import com.pnfsoftware.jeb.util.format.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;

/**
 * @author Cedric Lucas
 *
 */
public class DatabaseReferenceFile {
    private final ILogger logger = GlobalLog.getLogger(DatabaseReferenceFile.class);

    /*  may be null: could be defined to kick the bad candidates */
    // private DatabaseReferenceFile parent;

    public String file;
    private Map<String, Integer> versions;
    private List<String> merged = new ArrayList<>();

    public DatabaseReferenceFile(String file, Map<String, Integer> versions) {
        this.file = file;
        this.versions = versions;
    }

    void mergeVersions(Collection<MethodSignature> values) {
        if(versions == null) {
            versions = new HashMap<>();
        }
        for(MethodSignature value: values) {
            // put first as reference
            String[] versionsArray = value.getVersions();
            if(versionsArray == null) {
                // sig1 or no version specified
                increment(versions, "all");
            }
            else {
                List<String> versionsList = Arrays.asList(versionsArray);
                if(versions.isEmpty()) {
                    merged.addAll(versionsList);
                }
                else if(!merged.isEmpty()) {
                    List<String> tmp = CollectionUtil.intersection(versionsList, merged);
                    if(tmp.isEmpty()) {
                        // 2 options: either method is wrong or old method included
                        // it means that we make the choice here that previous version is still the good one
                        // (there must have been a validation before adding a whole class, so it makes sense)
                        logger.warn("Method %s->%s %s can not be found for current version", value.getCname(),
                                value.getMname(), value.getShorty());
                    }
                    else {
                        merged = tmp;
                    }
                }
                for(String v: versionsArray) {
                    increment(versions, v);
                }
            }
        }
    }

    static void increment(Map<String, Integer> versionOccurences, String key) {
        Integer val = versionOccurences.get(key);
        if(val == null) {
            versionOccurences.put(key, 1);
        }
        else {
            versionOccurences.put(key, val + 1);
        }
    }

    boolean hasNoVersion() {
        return versions == null || (versions.size() == 1 && versions.containsKey("all"));
    }

    public List<String> getMergedVersions() {
        return merged;
    }

    public Set<String> getAvailableVersions() {
        if(merged != null && !merged.isEmpty()) {
            return new HashSet<>(merged);
        }
        if(hasNoVersion()) {
            return null;
        }
        return versions.keySet();
    }

    List<List<String>> getOrderedVersions() {
        if(hasNoVersion()) {
            return new ArrayList<>();
        }
        Map<Integer, List<String>> versionsRev = versions.entrySet().stream().collect(
                Collectors.groupingBy(Map.Entry::getValue, Collectors.mapping(Map.Entry::getKey, Collectors.toList())));
        versionsRev = new TreeMap<>(versionsRev);
        List<List<String>> ordered = new ArrayList<>();
        VersionComparator vsCmp = new VersionComparator();
        for(Entry<Integer, List<String>> entry: versionsRev.entrySet()) {
            List<String> vs = new ArrayList<>(entry.getValue());
            Collections.sort(vs, vsCmp);
            Collections.reverse(vs);
            ordered.add(vs);
        }
        Collections.reverse(ordered);
        return ordered;
    }

    private static class VersionComparator implements Comparator<String> {
        @Override
        public int compare(String v1, String v2) {
            boolean v1Test = Strings.contains(v1.toLowerCase(), "rc", "alpha", "beta", "snapshot");
            boolean v2Test = Strings.contains(v1.toLowerCase(), "rc", "alpha", "beta", "snapshot");
            if(v1Test) {
                return v2Test ? v1.compareTo(v2): 1;
            }
            return v2Test ? -1: v1.compareTo(v2);
        }
    }

    public Set<String> getReducedVersions() {
        Set<String> versionList = new TreeSet<>(new VersionComparator());
        for(String v: merged) {
            versionList.add(v.replace("_d8r", "").replace("_d8d", "").replace("_d8", ""));
        }
        return versionList;
    }
}
