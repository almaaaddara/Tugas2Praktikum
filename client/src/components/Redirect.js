import axios from "axios";
import React, { useState, useEffect} from "react";
import { useNavigate, useSearchParams } from "react-router-dom";

import { useCookies } from "react-cookie";
import { jwtDecode } from "jwt-decode";

import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const Redirect = () => {
    const navigate = useNavigate();
    const [searchParams, setSearchParams] = useSearchParams();
    const [cookie, setCookie, removeCookie] = useCookies(["token"]);

    const [completed, setCompleted] = useState(false);

    const logout = () => {
        try {
            axios.delete("http://localhost:5000/logout")
            .then((res) => {
                console.log(res);
                removeCookie("token");
            }).catch((error) => {
                console.log(error);
            });
        } catch (error) {
            console.log(error);
        }
    }

    useEffect(() => {
        try {
            axios.get(`http://localhost:5000/verify?token=${searchParams.get("token")}`)
            .then((res) => {
                console.log(res);
                logout();
                setCompleted(true);
                toast.success("Verification completed.");
            }).catch((error) => {
                console.log(error);
                toast.error("Verification failed.");
            });
        } catch (error) {
            console.log(error);
            toast.error("Server error.");
        }
    }, []);

    return (
        <>
            <ToastContainer />
            <div className="m-10">
                {completed ? <h1 className="text-2xl font-bold text-gray-900">Verification completed click here to <a href="/login" className="text-blue-900 hover:underline hover:cursor-pointer">login</a></h1> : <h1 className="text-2xl font-bold text-gray-900">Redirecting...</h1>}
            </div>
        </>
    )
}

export default Redirect;