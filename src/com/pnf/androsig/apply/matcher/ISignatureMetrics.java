/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.matcher;

import java.util.Map;

import com.pnf.androsig.apply.model.LibraryInfo;

/**
 * @author clucas
 *
 */
public interface ISignatureMetrics {
    int getAllSignatureCount();

    int getAllUsedSignatureFileCount();

    Map<String, LibraryInfo> getAllLibraryInfos();
}
