/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import com.pnf.androsig.apply.model.MethodSignature;

/**
 * @author Cedric Lucas
 *
 */
public class DatabaseReferenceFile {

    public String file;
    public Map<String, Integer> versions;

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
            String[] versionsArray = MethodSignature.getVersions(value);
            if(versionsArray == null) {
                // sig1 or no version specified
                increment(versions, "all");
            }
            else {
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
}
