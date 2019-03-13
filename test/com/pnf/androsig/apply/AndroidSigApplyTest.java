/*
 * JEB Copyright (c) PNF Software, Inc.
 * All rights reserved.
 * This file shall not be distributed or reused, in part or in whole.
 */
package com.pnf.androsig.apply;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

import org.junit.Ignore;
import org.junit.Test;

import com.pnf.androsig.JebContext;
import com.pnf.androsig.apply.andsig.AndroidSigApplyPlugin;
import com.pnfsoftware.jeb.core.Artifact;
import com.pnfsoftware.jeb.core.IArtifact;
import com.pnfsoftware.jeb.core.IEnginesContext;
import com.pnfsoftware.jeb.core.IRuntimeProject;
import com.pnfsoftware.jeb.core.exceptions.JebException;
import com.pnfsoftware.jeb.core.input.FileInput;
import com.pnfsoftware.jeb.util.io.IO;

/**
 * @author Cedric Lucas
 *
 */
public class AndroidSigApplyTest {

    protected void simpleTest() throws JebException, IOException {
        File generatedReport = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping.txt");
        IEnginesContext context = JebContext.getEnginesContext();
        context.getDataProvider().getPluginStore().getStoreLocation();
        IRuntimeProject prj = context.loadProject("sig-gen-test-obf.dex");
        File file = new File("testdata/dex", "sig-gen-test-obf.dex");
        IArtifact artifact = new Artifact(file.getName(), new FileInput(file));
        /*ILiveArtifact art =*/ prj.processArtifact(artifact);

        AndroidSigApplyPlugin plugin = new AndroidSigApplyPlugin();
        plugin.execute(context, new HashMap<>());

        // assertions
        assertTrue(IO.compareFiles(new File("testdata/mapping", "androsig-mapping.txt"), generatedReport));
        // TODO validate classes are updated
    }

    @Test
    public void testGenSigGen() throws JebException, IOException {
        new File("testdata/out/android_sigs").mkdirs();
        File generated = new File("testdata/out/android_sigs/sig-gen-test_dex.sig");
        File orig = new File("testdata/sig/sig-gen-test.sig");
        IO.copyFile(orig, generated, true);

        try {
            simpleTest();
        }
        finally {
            // clean up
            if(generated.exists()) {
                generated.delete();
            }
            File generatedReport = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping.txt");
            if(generatedReport.exists()) {
                generatedReport.delete();
            }
        }
    }

    @Test
    public void testConflictGenSigGen1() throws JebException, IOException {
        new File("testdata/out/android_sigs").mkdirs();
        File generated = new File("testdata/out/android_sigs/sig-gen-test_dex.sig");
        File orig = new File("testdata/sig/sig-gen-test.sig");
        IO.copyFile(orig, generated, true);
        File generated3 = new File("testdata/out/android_sigs/sig-gen-test_dex-3.sig");
        File orig3 = new File("testdata/sig/sig-gen-test-3.sig");
        IO.copyFile(orig3, generated3, true);

        try {
            simpleTest();
        }
        finally {
            // clean up
            if(generated.exists()) {
                generated.delete();
            }
            if(generated3.exists()) {
                generated3.delete();
            }
            File generatedReport = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping.txt");
            if(generatedReport.exists()) {
                generatedReport.delete();
            }
        }
    }

    @Test
    public void testConflictGenSigGen2() throws JebException, IOException {
        new File("testdata/out/android_sigs").mkdirs();
        File generated = new File("testdata/out/android_sigs/sig-gen-test_dex.sig");
        File orig = new File("testdata/sig/sig-gen-test-3.sig");
        IO.copyFile(orig, generated, true);
        File generated3 = new File("testdata/out/android_sigs/sig-gen-test_dex-3.sig");
        File orig3 = new File("testdata/sig/sig-gen-test.sig");
        IO.copyFile(orig3, generated3, true);

        try {
            simpleTest();
        }
        finally {
            // clean up
            if(generated.exists()) {
                generated.delete();
            }
            if(generated3.exists()) {
                generated3.delete();
            }
            File generatedReport = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping.txt");
            if(generatedReport.exists()) {
                generatedReport.delete();
            }
        }
    }

    @Test
    public void testGenSigGenId() throws JebException, IOException {
        new File("testdata/out/android_sigs").mkdirs();
        File generated = new File("testdata/out/android_sigs/sig-gen-test_dex.sig");
        File orig = new File("testdata/sig/sig-gen-test.sig");
        IO.copyFile(orig, generated, true);
        File generatedReport = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping.txt");

        try {
            IEnginesContext context = JebContext.getEnginesContext();
            context.getDataProvider().getPluginStore().getStoreLocation();
            IRuntimeProject prj = context.loadProject("sig-gen-test.dex");
            File file = new File("testdata/dex", "sig-gen-test.dex");
            IArtifact artifact = new Artifact(file.getName(), new FileInput(file));
            /*ILiveArtifact art =*/ prj.processArtifact(artifact);

            AndroidSigApplyPlugin plugin = new AndroidSigApplyPlugin();
            plugin.execute(context, new HashMap<>());

            // assertions
            assertTrue(IO.compareFiles(new File("testdata/mapping", "androsig-mapping-id.txt"), generatedReport));
            // TODO validate classes are updated
        }
        finally {
            // clean up
            if(generated.exists()) {
                generated.delete();
            }
            if(generatedReport.exists()) {
                generatedReport.delete();
            }
        }
    }

    @Ignore
    @Test
    public void testNonObfuscated() throws JebException, IOException {
        new File("testdata/out/android_sigs").mkdirs();
        File generated = new File("testdata/out/android_sigs/support-fragment-28_0_0.sig");
        File orig = new File("testdata/sig/support-fragment-28_0_0.sig");
        IO.copyFile(orig, generated, true);
        File generatedReport = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping.txt");

        try {
            IEnginesContext context = JebContext.getEnginesContext();
            context.getDataProvider().getPluginStore().getStoreLocation();
            IRuntimeProject prj = context.loadProject("sig-gen-test.dex");
            File file = new File("testdata/apk", "app-release-unsigned.apk");
            IArtifact artifact = new Artifact(file.getName(), new FileInput(file));
            /*ILiveArtifact art =*/ prj.processArtifact(artifact);

            AndroidSigApplyPlugin plugin = new AndroidSigApplyPlugin();
            plugin.execute(context, new HashMap<>());

            // assertions
            assertTrue(
                    IO.compareFiles(new File("testdata/mapping", "androsig-mapping-releaseapk.txt"), generatedReport));
            // TODO validate classes are updated
        }
        finally {
            // clean up
            if(generated.exists()) {
                generated.delete();
            }
            if(generatedReport.exists()) {
                generatedReport.delete();
            }
        }
    }

    @Ignore
    @Test
    public void testObfuscated() throws JebException, IOException {
        new File("testdata/out/android_sigs").mkdirs();
        File generated = new File("testdata/out/android_sigs/support-fragment-28_0_0.sig");
        File orig = new File("testdata/sig/support-fragment-28_0_0.sig");
        IO.copyFile(orig, generated, true);
        File generatedReport = new File(System.getProperty("java.io.tmpdir"), "androsig-mapping.txt");

        try {
            IEnginesContext context = JebContext.getEnginesContext();
            context.getDataProvider().getPluginStore().getStoreLocation();
            IRuntimeProject prj = context.loadProject("sig-gen-test.dex");
            File file = new File("testdata/apk", "app-release-unsigned--pg-repackageclasses.apk");
            IArtifact artifact = new Artifact(file.getName(), new FileInput(file));
            /*ILiveArtifact art =*/ prj.processArtifact(artifact);

            AndroidSigApplyPlugin plugin = new AndroidSigApplyPlugin();
            plugin.execute(context, new HashMap<>());

            // assertions
            assertTrue(
                    IO.compareFiles(new File("testdata/mapping", "androsig-mapping-releasepgapk.txt"),
                            generatedReport));
            // TODO validate classes are updated
        }
        finally {
            // clean up
            if(generated.exists()) {
                generated.delete();
            }
            generatedReport.renameTo(new File(System.getProperty("java.io.tmpdir"), "androsig-mapping-idd.txt"));
            if(generatedReport.exists()) {
                generatedReport.delete();
            }
        }
    }

}
