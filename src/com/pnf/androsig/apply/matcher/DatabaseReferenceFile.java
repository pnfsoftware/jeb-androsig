/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.Map;

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
}
