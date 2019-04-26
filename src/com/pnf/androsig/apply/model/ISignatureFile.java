/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply.model;

import java.io.Closeable;
import java.util.List;
import java.util.Map;

/**
 * @author Cedric Lucas
 *
 */
public interface ISignatureFile extends Closeable {

    Map<String, LibraryInfo> getAllLibraryInfos();

    List<MethodSignature> getTightSignatures(String hashcode);

    List<MethodSignature> getLooseSignatures(String hashcode);

    List<MethodSignature> getSignaturesForClassname(String className, boolean exactName);

    int getAllSignatureCount();

}
